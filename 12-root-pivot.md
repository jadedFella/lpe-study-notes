# Chapter 12 — From a fake cred to a real root shell

Goal of this chapter: after chapter 11 the worker's `cred` pointer is a lie.
This chapter follows how the exploit converts that lie into a real login as
root: an oracle that notices the exact moment the fake cred arrives, a setuid
file created with it, a helper process that detonates it, and a root shell.

References: PoC `stage_helper()` (179–221), `do_escalate()` (223–271),
`warm_splice_pipe()` (273–290), `pick_staging_dir()` (1417–1457),
`run_launcher()` (1396–1415), `main()` (1459–1540), and the attempt tail
(1362–1380).

## 1. What exactly was forged — and what was not

After the two erases (chapter 11), the winning worker's `task_struct` has:

- `cred` → our page-resident fake cred with `uid..fsgid = 0`, all five
  capability sets `= ~0`, an AppArmor label flagged "unconfined", and a fake
  user namespace;
- `real_cred` → **unchanged** (the original unprivileged cred).

What uses which? Permission checks (`capable()`, `inode_permission()`,
`file_owner()`, LSM hooks) all consult `current_cred()` — the effective cred —
so as far as those are concerned, the worker *is* root. But plenty of kernel
paths also read `real_cred`, and the two are supposed to agree; keeping them
apart is why this exploit's post-write phase **is careful about which syscalls
it performs**: only file operations (`openat`, `newfstatat`, `sendfile`,
`fchmod`, `write`), never `execve` from the corrupted thread.

There is a second, simpler reason to avoid `execve` in the worker: it *is* a
thread. Exec from any thread replaces the entire process image (`de_thread`,
chapter 5), which would kill the orchestrator, the launcher, and the other 391
workers. The shell must be spawned elsewhere.

## 2. The oracle: a file's owner

The worker runs this loop (`do_escalate`, 223–271) — note it is the *same
thread* that just performed the erases:

```c
	out = syscall(SYS_openat, AT_FDCWD, path,
		      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (out < 0)
		return 0;
	if (syscall(SYS_newfstatat, out, "", &st, AT_EMPTY_PATH) || st.st_uid) {
		close(out); unlink(path);
		return 0;
	}
	... /* copy, chmod, announce */
```

`path` is a fresh name (`g_helper_path.SEQ`) created with `O_EXCL`, so each
iteration makes a brand-new file. The file was created *by this thread*, and
Linux stamps new files with the creator's **fsuid** (`current_fsuid()`). So:

- before the erase: `st.st_uid` = the worker's normal uid → the check fails,
  the file is cleaned up, the loop tries again;
- after the erase: `fsuid` in the fake cred is `0` → the next file is owned by
  `root` → `st_uid == 0` → the oracle fires.

That is why the loop is entered *while* the worker burns CPU (chapter 11 §4):
the moment the `rb_erase` stores land, the very next iteration notices. No
cross-thread signalling, no polling protocol — the observable side effect of
the forged cred is used as its own confirmation.

## 3. Turning the lie into a file with the `setuid` bit

Once `st_uid == 0` (247–270), the same forged creds let the worker do things
an unprivileged worker cannot:

1. Copy the exploit binary into the new file:
   `sendfile(out, g_src_fd, &off, 1MB)` in a loop until EOF. `g_src_fd` is an
   already-open fd to `/proc/self/exe` (set up in `stage_helper`, 210), so no
   path lookup or permission re-check of `/proc/self/exe` happens in the
   corrupted state.
2. `fchmod(out, 04755)` — setuid root, `rwxr-xr-x`. This needs
   `CAP_FOWNER`/ownership; the fake cred has both.
3. `write(g_launch_wfd, path, strlen(path) + 1)` — hand the path to the
   launcher.
4. `poc_success = 1`.

If the copy or chmod fails, the file is unlinked and the loop continues — the
worker attempts this for up to `STAGE2_RUN_NS` (1 second of its own CPU time),
which is many thousands of iterations.

Two pieces of preparation before all this:

- `pick_staging_dir()` (1417) chooses among `/var/tmp`, `/dev/shm`, `/tmp`:
  it must be writable, and the **longest-prefix mount entry** in
  `/proc/mounts` must not carry the `nosuid` option (`strstr(opts, "nosuid")`).
  On a `nosuid` mount the kernel ignores the setuid bit at exec time, so the
  pivot needs a "normal" filesystem.
- `stage_helper()` (179) reserves the base path and opens `g_src_fd`.
- `warm_splice_pipe()` (273) does one throwaway 4 KiB `sendfile` before the
  forgery. Its purpose is to exercise the sendfile→pipe machinery once with
  pristine credentials, so the real copy later takes the already-warm path
  (first-use allocation happens *now*, not in the odd credential state).

## 4. The launcher: a clean process to detonate the file

Early in `main()` (1497–1506), *before* any exploitation, the process forks a
launcher and hands it the read end of a pipe:

```c
	launcher = fork();
	if (launcher == 0) {
		close(launch_pipe[1]);
		...
		run_launcher(launch_pipe[0]);
	}
```

and `run_launcher()` (1396) is a five-line loop:

```c
	for (;;) {
		ssize_t n = read(rfd, path, sizeof(path) - 1);
		if (n > 0) {
			path[n] = '\0';
			execve(path, argv, envp);
			continue;
		}
		...
	}
```

The launcher is a completely normal, unprivileged process — its creds were
never touched. When it `execve()`s the `04755` file, the kernel applies the
ordinary setuid-exec rule: **the exec'd image gets `euid = owner = 0`**, while
the real `uid` stays the launcher's uid. No forged pointers are involved in
this transition; it is documented Unix privilege semantics, triggered by a
file we were allowed to create only because of the forged cred.

This is the pivot: *in-memory fake privilege* becomes a *real* credential
change, executed by a process the exploit never corrupted.

## 5. The new image becomes a shell

The binary re-enters `main()` (1459) and the first branch handles
"euid 0, uid != 0" — the classic setuid state:

```c
	if (!geteuid() && getuid()) {
		... unlink(self) ...                    /* leave no suid file behind */
		if (setresgid(0, 0, 0) || setresuid(0, 0, 0))
			_exit(126);
		execve("/bin/bash", shargv, shenv);     /* root shell */
		execve("/bin/sh", shargv, shenv);
		_exit(127);
	}
```

So what actually happens, end to end:

```
worker thread (fake cred)
    creates /var/tmp/.timer-poc-PID.SEQ, owner root          [oracle: uid == 0]
    copies the exploit binary into it
    chmod 04755
    writes the path into the pipe
        │
        ▼
launcher (clean creds)  read() -> execve(path)
        │
        ▼
new image: euid = 0 (setuid file), uid = unprivileged
    unlink itself
    setresgid/setresuid(0,0,0)
    execve("/bin/bash", "-i")
        │
        ▼
root shell
```

Note that the *same* binary serves three roles, distinguished by these first
lines: the normal exploit, the re-exec of the trigger, and — after the pivot —
the setuid image. The trigger role is recognised separately
(`is_reexec_image()`, 1383): it reads `/proc/self/cmdline`; if `argv[0]` is
empty, this image is the *re-exec* of the trigger (chapter 8 §3) and exits
with code 42.

## 6. Why nothing is cleaned up at the end

After `poc_success` is observed, `run_exploit_attempt()` returns 0, and the
attempt child writes a byte into `done_pipe` and then loops `pause()`
(1518–1522). The top-level parent, upon reading that byte, also `pause()`s
forever (1529–1532). 

The reason is the same as everywhere else in this exploit: fds, threads,
worker threads and the AIO arena are all *shared state* that other parts of
the machine (including the shell's session) may still depend on. Exiting the
exploit process at success could:
- close `g_launch_wfd` while the launcher is still reading,
- tear down the environment right as the shell starts,
- and generally race cleanup against a live root shell.

Parking both processes keeps the tree alive; the shell's own lifetime becomes
independent (it is the launcher's exec'd image). On failure, the cleanup path
(1362–1380) does the opposite: `cleanup_aio_spray()` plus a 2-second sleep to
let the kernel quiesce, unlink the helper, delete all staged timers, stop the
workers — then the parent tries a fresh child (`MAX_EXPLOIT_ATTEMPTS = 3`)
with a rebuilt heap.

## Hands-on

1. Read `do_escalate()` (223–271) and annotate each syscall with the
   permission it needs: which of them succeed *only* with the forged cred, and
   which would also succeed without it?
2. Read `main()` (1459–1540) and the launcher handoff. Answer: why can't the
   worker that owns the forged cred simply `execve("/bin/bash")` itself?
3. Read `pick_staging_dir()` (1417–1457). Explain the `best` / longest-prefix
   logic: what does it protect against if, say, `/dev/shm` is a `tmpfs`
   mounted `nosuid` while `/var/tmp` is on the root filesystem?
4. Walk the state of `uid`, `euid` through the pivot:
   - launcher before exec: `uid = 1000, euid = 1000`;
   - in the setuid image: `uid = ?, euid = ?`;
   - after `setresuid(0,0,0)`: `uid = euid = suid = 0`.
   Which of these transitions is enforced by the kernel regardless of the
   forged cred?
5. Answer: why does the exploit write the path and exit the loop *before*
   the shell exists, instead of waiting (say, for the shell to create a file)
   and only then claiming success? What race does `pause()`-parking avoid?
6. Extra: `warm_splice_pipe()` deliberately runs with pristine creds. Find
   one thing that would go wrong if the *first* `sendfile` of this process was
   the real one, in the forged state (there are several acceptable answers;
   argue from the syscall's needs, not from kernel internals).

## Checkpoint

1. Which `cred` field does `newfstatat`'s `st_uid` reflect, and why is that a
   perfect oracle for "the erase happened"?
2. What two privileged operations does the worker perform that the
   unprivileged version of itself could not, and which fake cred fields make
   them pass?
3. Why is the pivot executed by a *different* process, and what makes that
   process's `execve` give `euid = 0`?
4. What does the setuid image do in its first branch, in order?
5. Why do both the attempt child and the top-level parent `pause()` forever
   after success?
