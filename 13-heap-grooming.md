# Chapter 13 — Heap grooming: how the page comes back to us

Goal of this chapter: close the loop on the one step chapters 9–12 quietly
assumed — *the dangling node's page becomes a page we can read and write*.
This is the part of the exploit that is pure allocator engineering: RCU
batching, SLUB sheaves and barns, per-CPU page lists, and page-spraying. It
also finishes explaining every magic number in the PoC.

References: PoC `recycle_victim_into_oracle_pool` (957–975),
`create_release_timers`/`delete_release_range` (977–1008),
`create_slab_padding`/`delete_slab_padding` (1010–1034), `create_drain_pool`/
`delete_drain_pool` (1039–1064), `prime_order0_pcp` (1066–1084),
`allocate_aio_spray` (451–524), `prewarm_aio_allocator` (540–577),
`run_exploit_attempt` (1255–1381). Kernel side: `mm/slub.c` and
`kernel/time/posix-timers.c` release path.

## 1. Four levels to cross

When chapter 9 says "the object is freed", that is shorthand. The memory
travels through four layers before it is ours:

1. **RCU**: `posixtimer_free_timer()` uses `kfree_rcu(tmr, rcu)`
   (posix-timers.c:447). The object is queued; actual freeing waits for a
   grace period.
2. **SLUB**: after the callback runs, the 384-byte slot returns to the
   `posix_timers_cache` free pool. The containing slab page is still a slab.
3. **Page allocator**: only when every object in that slab page is free does
   SLUB *discard* the slab — the page becomes order-0 free. (SLUB keeps a few
   empty slabs per node as spare (`min_partial`); a large enough burst of
   frees pushes the surplus back to the buddy allocator.)
4. **Userspace**: the page must then be handed to an allocation whose contents
   we can read/write — an anonymous page fault or an AIO ring mapping.

The exploit cannot do 1–3 directly; it can only *feed the allocators* in a
pattern that makes them do it, at the right time. The pattern is built around
the SLUB implementation in the pre-fix tree.

## 2. SLUB in this kernel: sheaves and barns

Three structures (mm/slub.c:429–452):

```c
struct slab_sheaf {
	union {
		struct rcu_head rcu_head;
		struct list_head barn_list;
		struct llist_node llnode;
		struct { unsigned int capacity; bool pfmemalloc; };
	};
	struct kmem_cache *cache;
	unsigned int size;
	int node;
	void *objects[];
};

struct slub_percpu_sheaves {
	local_trylock_t lock;
	struct slab_sheaf *main;     /* never NULL when unlocked */
	struct slab_sheaf *spare;    /* empty or full, may be NULL */
	struct slab_sheaf *rcu_free; /* for batching kfree_rcu() */
};
```

A **sheaf** is a small array of *object pointers* (32-byte header + pointers),
allocated from kmalloc and used as a batching buffer. Each CPU has a `main`
sheaf it allocates from and frees into, plus a `spare`, plus one for batching
deferred frees (`kfree_rcu`). When sheaves are full they are parked in the
per-NUMA-node **barn** (slub.c:421–427):

```c
#define MAX_FULL_SHEAVES	10
#define MAX_EMPTY_SHEAVES	10
```

So the barn holds at most 10 full sheaves (free-pointer sources) and 10 empty
sheaves (receptacles) per node.

How many pointers fit in a sheaf? `calculate_sheaf_capacity()`
(slub.c:7871):

```c
	if (s->size >= PAGE_SIZE)      capacity = 4;
	else if (s->size >= 1024)      capacity = 12;
	else if (s->size >= 256)       capacity = 26;   /* <-- our cache */
	else                           capacity = 60;

	size = struct_size_t(struct slab_sheaf, objects, capacity);
	size = kmalloc_size_roundup(size);
	capacity = (size - struct_size_t(struct slab_sheaf, objects, 0)) / sizeof(void *);
```

Our cache's object size is 384 (`sizeof(struct k_itimer)` = 0x180), so:

```
capacity = 26
struct_size = 32 + 26*8 = 240   (header is 32 bytes)
kmalloc_size_roundup(240) = 256
capacity = (256 - 32) / 8 = 28
```

**One sheaf = 28 pointers. One barn = 10 × 28 = 280 pointers.** Every
constant in the PoC is a multiple of 28, and that is why:

| constant | value | meaning |
|---|---|---|
| `RCU_RECLAIM_FILLERS` | 279 | 279 + 1 victim = **280 = one barn** |
| `RCU_BARN_FILLERS` | 280 | one barn of frees |
| `ORACLE_WORKERS` | 392 = 14×28 | 14 sheaves of allocations |
| `SLAB_PADDING_TIMERS` | 4200 = 150×28 | 150 sheaves of long-lived objects |
| `DRAIN_POOL_TIMERS` | 16016 = 572×28 | 572 sheaves of frees in one burst |
| `RCU_RELEASE_TIMERS` | 820 = 280 + 540 | one barn + a reserve |

The RCU batcher (`rcu_free` sheaf) works in the same units: deferred frees
accumulate in a sheaf, and a full sheaf (28 objects) is handed to RCU as a
batch. Keep this picture: **the allocator moves memory in sheaf-sized
chunks.**

## 3. The choreography, step by step

Below is the order in `run_exploit_attempt()`, with *why* each step is there.
"us" = the attempt process (which forks the trigger and owns the workers).

### Before the trigger

1. `create_slab_padding()` — 4200 (150 sheaves) long-lived `SIGEV_NONE` timers
   (1285). Fills the cache's current sheaves and ends with the cache in a
   "shaped" state: its per-CPU sheaves and barns are populated, so the next
   allocations come from known places.
2. Fork the trigger; wait for its death *without reap*
   (`wait_zombie_without_reap`, chapter 8).

### Around the reap

3. `recycle_victim_into_oracle_pool()` — 279 create+delete cycles (1304).
   With the victim's released object, that is 280 frees = exactly one barn of
   `kfree_rcu` traffic. The point: the victim's object is *inside a full batch*
   when that batch is handed to RCU, so it is processed together with a known
   number of friends and its progress through the RCU/SLUB layers is
   predictable.
4. Sleep 3 s (`grace`) — let those callbacks run.
5. `allocate_oracle_candidates()` — 392 (14 sheaves) fresh candidate timers on
   the 392 workers (1309). These pop free pointers from the cache; 14 sheaves
   worth is enough churn that one of them is very likely to pop the victim's
   slot. `timer_settime` then links each candidate's node into its worker's
   queue **before** the reap.
6. `waitpid()` (1313) — **the reap and the UAF write of chapter 8**, while the
   object still belongs to a live worker (chapter 9's transfer).

### The heap work that empties the slab

7. `create_release_timers()` — 820 (280 + 540) timers, allocated fresh
   (1317).
8. `create_drain_pool()` — 16016 (572 sheaves) timers (1320).
9. `prewarm_aio_allocator()` (1323) — 128 small + 48 large AIO setups, all
   destroyed, then a 1 s settle. This warms the AIO allocation path and the
   page cache machinery so the real spray (§11) is uniform and fast.
10. Release the 820 timers in **three waves** with sleeps (1327–1338):
    `[0,280)`, `[280,540)`, `[540,820)`, each followed by 3 s. Each wave is a
    batch of `kfree_rcu` frees flushed through RCU separately; the waves
    *steer when* pages lose their last objects. The middle wave plus
    `RCU_DRAIN_KICK` is why the constants are split 280 / 260 / 280.
11. `delete_oracle_candidates()` (1340) — the transfer of chapter 9. The
    *other* 391 candidates free normally; each is one k_itimer in some slab.
12. `delete_slab_padding()` (1342) — release the 4200 shaping objects, then
    sleep 1 s (`victim_grace`). With the candidates' pages now mostly empty,
    this marks the slab side of the cache as "many freed objects".
13. `prime_order0_pcp()` (1347) — mmap 8192 pages (32 MiB), touch every page,
    munmap. This is *page allocator* work, not slab work: it fills the per-CPU
    page lists (PCP) with 8192 order-0 pages **we allocated**, in LIFO order.
14. `delete_drain_pool()` (1350) — 16016 frees in one burst, then sleep
    300 ms (`drain_grace`). This is the step that pushes the slab pages
    (including the page our dangling node lives in) out of SLUB and back to
    the page allocator: hundreds of slabs empty at once, far past
    `min_partial`, so SLUB discards them — straight onto the PCP lists.
    And because PCP is a stack and we primed it in step 13, **the pages freed
    last are handed out first**.

### The reclaim

15. `allocate_aio_spray()` (1352) — allocate 64000 anonymous pages, then
    ~64000 AIO ring pages:

    ```c
	spray->anon = mmap(NULL, 64000 * 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	madvise(spray->anon, ..., MADV_NOHUGEPAGE);
	for (i = 0; i < 64000; i++) prepare_aio_page(anon + i*4096);

	/* AIO: one io_setup(1) per ring; each ring mremap'ed to a fixed slot of a
	   pre-reserved PROT_NONE arena; every mapped ring page gets the template */
    ```

    The first faults touch pages just freed by the drain: LIFO PCP pops the
    drain pages first, so a large fraction of these 128000 stamped pages are
    pages that *were* slab pages moments ago — including our victim page. AIO
    rings are used as a second, independent source of *kernel-allocated but
    user-mapped* pages; the PoC reads the ring header (484–503) to size each
    ring dynamically (rings can span multiple pages depending on the kernel's
    events-per-page).

    The template (`prepare_aio_page`, chapter 10 §2) is written *after* each
    mapping exists, so every reclaimed page is ready to be "the" page.

16. `run_stage1()` — the scan (chapter 10) finds the single page whose
    `handling` slot got a kernel pointer. With 128000 candidate pages against
    ~16000-odd freed objects' worth of pages, the odds are lopsided in our
    favor.

## 4. Why this is reliable rather than lucky

Three independent allies:

- **RCU gives the exploit time.** `kfree_rcu` batching means the exploit can
  *schedule* frees into a future grace period and sleep; it never races a
  synchronous free path.
- **PCP is a stack.** Prime it, then free the target pages, then allocate:
  LIFO ordering turns "some free page" into "very likely *the* page".
- **SLUB batching is our unit system.** The sheaf/barn granularity (28) lets
  the PoC use counts that translate directly into "N pages finish freeing in
  this wave". This is what the `recycle` (279+1), `release` (820), `padding`
  (4200) and `drain` (16016) numbers mean.

And one honest caveat: these constants are **target-specific**. They were
derived for the SLUB implementation in this kernel source (pre-fix
`d2710c8d938a`) with its sheaf capacity of 28. On a kernel with a different
SLUB (for example this machine's Ubuntu 6.14, which has the older
`cpu_partial` design where sheaf knobs do not exist) the arithmetic changes
completely; chapter 14's "derive your constants" section is the general
method.

## 5. Failure and retry

On any failure, `run_exploit_attempt` (1362–1380) cleans up carefully:

```c
	if (result != 0 && spray_ready) {
		cleanup_aio_spray(&spray);           /* io_destroy every ring */
		nanosleep(&aio_recover /* 2 s */);
	}
	if (result != 0 && g_helper_fd >= 0) { close; unlink; }
	if (drain_pool_count) delete_drain_pool();
	delete_release_range(&release, 0, release.count);
	delete_slab_padding(padding);
	destroy_timer_oracle(&oracle);          /* stop + join all 392 workers */
```

The 2-second `aio_recover` sleep exists because destroying tens of thousands of
AIO contexts itself floods RCU and the page allocator; the next attempt should
start from a quiet system. `main()` then forks a **fresh child** for the next
attempt (up to `MAX_EXPLOIT_ATTEMPTS = 3`), so each attempt gets a fresh
address space, fresh workers, and a re-run of the whole choreography.

## Hands-on

1. Verify the sheaf arithmetic from source. Read
   `mm/slub.c` lines 7871–7916 (`calculate_sheaf_capacity`), lines 418–445
   (`MAX_FULL_SHEAVES`, `struct slab_sheaf`) and confirm: 384-byte objects →
   capacity 26 → rounded to 256 → 28 pointers per sheaf. Then check every PoC
   constant against 28.
2. On your machine (no root needed for the first command):
   ```
   uname -r
   ls /sys/kernel/slab/posix_timers_cache/
   ```
   On this machine (Ubuntu 6.14) you will see the *old* SLUB attributes
   (`cpu_partial`, `slabs_cpu_partial`, …) and **no** `sheaf_capacity` — proof
   that the target kernel's SLUB flavour matters. (The `sheaf_capacity` sysfs
   attribute exists in the pre-fix tree at slub.c:9208.)
3. In the PoC, find the definition of every constant in the §2 table and
   write one sentence per constant: which allocator layer it feeds (slab
   churn, RCU batch, PCP priming, coverage) and what would change if you
   doubled it (too small = misses, too large = slower and more dmesg noise).
4. Answer: why must `prime_order0_pcp()` run **after**
   `delete_slab_padding()` and **before** `delete_drain_pool()`? What
   precisely does swapping the last two steps break? (Think in terms of the
   PCP stack order relative to which pages get freed when.)
5. Answer: the drain pool is created *after* the reap but its objects are
   ordinary timers that are never pointed at by anything stale. Why does
   deleting *them* help free *our* object's page? (Trace: what determines
   when a slab page is discarded by SLUB?)
6. Extra: `allocate_aio_spray` requires at least 1024 ready pages
   (line 523). Where do the numbers 64000 (`AIO_SPRAY_PAGES`,
   `ANON_SPRAY_PAGES`) and `AIO_SPRAY_USE` come from in the code, and what
   would the scan cost be if you cut them by 10×? Which failure mode gets
   more likely?

## Checkpoint

1. Name the four layers the freed object passes through, with the function
   that does each hand-off.
2. What is a sheaf in this SLUB, and how many object pointers does one hold for
   this cache? Show the arithmetic.
3. Give the barn sizes and explain why `279 + 1` and `392` and `16016` are all
   multiples of 28.
4. Why does the exploit touch 8192 pages and unmap them right before the big
   drain? Which allocator property is it exploiting?
5. Why are the 820 release timers freed in three waves with sleeps instead of
   all at once?
6. What exactly makes the victim's slab page leave SLUB and become an
   ordinary free page, and what makes it likely to become one of *our*
   sprayed pages?
