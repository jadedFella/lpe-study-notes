# Chapter 4 — The timerqueue: an RB tree with a cached leftmost node

Goal of this chapter: understand what a `timerqueue` is, what every field of
an `rb_node` means, how insertion/lookup/deletion work at the level we need,
and — most importantly — what it will mean when we say "the tree still points
at a node whose memory was freed and reused".

## 1. Why a tree at all?

Many timers can be armed at once, each with an expiry time. The kernel must:

- insert a timer cheaply (hundreds or thousands can exist),
- remove one by pointer (when you delete it), and
- always know *which timer expires next* (the tick fires the earliest one).

A sorted structure gives all three; a balanced binary tree keeps the depth
~log2(n) instead of degenerating into a long chain. The kernel uses a
**red-black tree** — a self-balancing binary tree.

You do **not** need to know the balancing rules (rotations, recoloring) for
this book. We only touch two things: the node layout, and one branch of the
deletion code (section 7).

## 2. `struct rb_node` and the packed parent+color trick

`include/linux/rbtree_types.h`:

```c
struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
```

- `rb_left` points to the child with a *smaller* key, `rb_right` to the
  child with a *larger* key. For timers the key is `expires`, so "leftmost"
  means "earliest expiry".
- `__rb_parent_color` stores the parent pointer **and** the node's red/black
  color in one word. Pointers are at least 4-byte aligned, so the low bits of
  a pointer are always free; the color lives in bit 0:

  ```c
  #define __rb_parent(pc) ((struct rb_node *)(pc & ~3))
  #define __rb_is_black(pc) ((pc) & 1)
  ```

- `RB_CLEAR_NODE(node)` writes the node's *own address* into
  `__rb_parent_color`. `RB_EMPTY_NODE(node)` checks for that value. It means
  "this node is not currently in any tree" — a self-marker. You will see it
  set after a node is removed.

## 3. The timerqueue types

`include/linux/timerqueue_types.h`:

```c
struct timerqueue_node {
	struct rb_node node;
	ktime_t        expires;
};

struct timerqueue_head {
	struct rb_root_cached rb_root;
};
```

and `include/linux/rbtree_types.h`:

```c
struct rb_root_cached {
	struct rb_root  rb_root;
	struct rb_node *rb_leftmost;   /* cached leftmost = earliest expiry */
};
```

So a queue head is: a root pointer plus a cached "earliest" pointer. Keeping
the leftmost cached makes "what expires next?" an O(1) read instead of a walk
down the left spine.

## 4. The three operations

`lib/timerqueue.c`:

```c
bool timerqueue_add(struct timerqueue_head *head, struct timerqueue_node *node)
{
	/* Make sure we don't add nodes that are already added */
	WARN_ON_ONCE(!RB_EMPTY_NODE(&node->node));

	return rb_add_cached(&node->node, &head->rb_root, __timerqueue_less);
}

bool timerqueue_del(struct timerqueue_head *head, struct timerqueue_node *node)
{
	WARN_ON_ONCE(RB_EMPTY_NODE(&node->node));

	rb_erase_cached(&node->node, &head->rb_root);
	RB_CLEAR_NODE(&node->node);

	return !RB_EMPTY_ROOT(&head->rb_root.rb_root);
}
```

and `include/linux/timerqueue.h`:

```c
static inline struct timerqueue_node *timerqueue_getnext(struct timerqueue_head *head)
{
	struct rb_node *leftmost = rb_first_cached(&head->rb_root);

	return rb_entry_safe(leftmost, struct timerqueue_node, node);
}
```

Notice what these functions take as arguments: a **head** and a **node
address**. Nothing in the tree stores a back-pointer to the object that owns
the node, and nothing in the tree stores the queue head inside the node.
The tree only knows addresses and key values.

## 5. `head`: the object's memory of its queue

Recall from chapter 3 that `struct cpu_timer` has both a `node` (what the
tree stores) and a `head` (a pointer *to the queue*). Synchronization between
"am I in a tree" and "does `head` say so" is the object's own job
(`include/linux/posix-timers.h:81`):

```c
static inline bool cpu_timer_dequeue(struct cpu_timer *ctmr)
{
	if (ctmr->head) {
		timerqueue_del(ctmr->head, &ctmr->node);
		ctmr->head = NULL;
		return true;
	}
	return false;
}
```

Compare the two removal styles:

- **By iteration** (`cleanup_timerqueue`, the reap path): `while
  ((node = timerqueue_getnext(head))) timerqueue_del(head, node);` — it never
  consults `head`; it keeps pulling the leftmost node until the tree is
  empty.
- **By object** (`disarm_timer`, the delete/exit paths): it goes through
  `cpu_timer_dequeue()`, which trusts `ctmr->head` **as the truth** about
  whether the node is in a tree.

If those two views ever disagree — "the tree still points at me" vs
"`head` says I'm not queued" — the code will do the wrong thing. The exploit
(chapter 9) manufactures exactly that disagreement: it makes `head` NULL
while the node is still linked in a live task's tree. Later,
`cpu_timer_dequeue()` returns `false` and the object gets freed without the
node ever being removed.

## 6. Byte offsets on the exploit's target

Because a `cpu_timer` starts at offset 0xe0 inside `k_itimer` on the tested
target, the field offsets inside the object are:

| offset | field |
|---|---|
| 0xe0 | `node.__rb_parent_color` (parent + color) |
| 0xe8 | `node.rb_right` |
| 0xf0 | `node.rb_left` |
| 0xf8 | `node.expires` |
| 0x100 | `head` |
| 0x110 | `elist` (firing list) |
| 0x120 | `firing` |
| 0x128 | `handling` |

These numbers come from the PoC's BTF data for its target; other kernels will
differ. We'll use them when walking the exploit code.

## 7. The erase branch we will weaponize

`rb_erase_cached()` is the general RB deletion. `__rb_erase_augmented()` in
`include/linux/rbtree_augmented.h` handles three shapes. Here is the exact
branch the exploit drives (around line 268):

```c
	} else if (!child) {
		/* Still case 1, but this time the child is node->rb_left */
		tmp->__rb_parent_color = pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		__rb_change_child(node, tmp, parent, root);
		rebalance = NULL;
		tmp = parent;
	}
```

with `child = node->rb_right` and `tmp = node->rb_left` set above. Read it
carefully — this is where the exploit gets its arbitrary write:

1. `child` is NULL, so the deleted node has **no right child**; `tmp` is its
   **left child** (or NULL — but here non-NULL).
2. `tmp->__rb_parent_color = node->__rb_parent_color` — the erase **copies a
   word from the deleted node into the memory addressed by its left child
   pointer**. In C pointers: `*(void **)left_child = node->parent_field`.
3. `__rb_change_child(node, tmp, parent, root)` — if the node had a parent,
   it replaces the parent's left/right pointer (which one is checked by
   `parent->rb_left == node`); if it had none, it writes `root->rb_node =
   tmp`.

Both the *address* and the *value* of step 2 come from the node's own bytes.
If the node lives in memory an attacker controls, step 2 is a controlled
8-byte write, and step 3 is a second one. Chapter 11 turns this into
`task->cred = fake_cred`, after we discuss how to get control of that memory.

## 8. "The tree still points at a freed node"

Put sections 4 and 5 together: a task's record stores
`posix_cputimers.bases[2].tqhead`, whose `rb_root.rb_node` is just a raw
pointer to a node address. Nothing verifies that the object at that address
still exists, or still belongs to this task, or that anything is even
attached to it.

So "a UAF in a timerqueue" concretely means: some task's tree root still
contains an address, but the memory at that address has been freed (and
possibly reallocated as something else entirely). The next
`timerqueue_getnext()` or `timerqueue_del()` on that tree will follow and
write through those stale bytes — as if they were still a live node of this
queue.

## Hands-on

1. **Paper exercise.** Insert expiries 50, 30, 80, 10, 40 (in that order)
   into a binary tree where left = earlier. After each insert, write down the
   leftmost node. Then delete 10 and 30, and after each deletion write down
   the new leftmost. This is all the tree knowledge you need for the exploit.
2. Read `lib/timerqueue.c` and `include/linux/timerqueue.h` end to end —
   they are small.
3. Open `rbtree_augmented.h` around lines 245–275 and find the `!child`
   branch from section 7. Match each line to the three-step description.
4. In `posix-cpu-timers.c`, find `cleanup_timerqueue()` and `disarm_timer()`,
   and confirm which one uses `head` and which one iterates `getnext`.

## Checkpoint

1. What does the low bit of `__rb_parent_color` mean, and why is it legal to
   store it in the pointer?
2. What does `timerqueue_getnext()` rely on? Where is that value updated?
3. What does `RB_CLEAR_NODE` mark, and which function sets it after a removal?
4. In the `!child` erase branch, exactly which memory does the first write
   touch, and where do the address and value come from?
5. Why can't the tree "notice" that the object behind a node address was
   freed? (Answer in terms of what the tree stores.)
