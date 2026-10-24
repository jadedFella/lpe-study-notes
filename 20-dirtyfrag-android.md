# Chapter 20 — DirtyFrag: a page-cache write through ESP, and an Android root chain

This chapter is a case study, not part of the timer story. It looks at
CVE-2026-43284 ("DirtyFrag") and the Android port that uses it to load
KernelSU without unlocking the bootloader.

The bug is interesting because it is not a race and it does not corrupt a
kernel object. It gives an ordinary app a controlled write into the page cache
of files it can only read. The Android chain is interesting because that write
is enough to patch three files in RAM, borrow `init` for a few instructions,
and load a kernel module.

The public code discussed here is the DirtyFrag fork of DFRoot:

- <https://github.com/mitschud/DirtyFrag>
- <https://github.com/diabl0w/DFRoot>

The upstream Linux write-up is:

- <https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md>

## Goal

By the end of this chapter you should be able to explain:

- why `splice()` plus ESP decryption can write to a file's page cache;
- why the write is deterministic and why the file on disk is unchanged;
- how a 16-byte write becomes a controlled write using AES-CBC and a chosen IV;
- how the Android chain turns that into `init` code execution and a kernel
  module load;
- why a full reboot removes root, while a soft reboot may not;
- why KernelSU can say "Working" while `/system/bin/su` still fails.

## 1. The bug in one sentence

`esp_input()` is allowed to decrypt an ESP packet in place when the skb is
uncloned and nonlinear but has no `frag_list`. If one of those frags is a page
cache page planted by `splice()`, the in-place decryption writes plaintext
into the file's page cache.

The missing check is the ownership check. `esp_input()` should call
`skb_cow_data()` when a frag is shared with someone else. The fast path assumes
the skb owns its frags. A page cache page pinned by a pipe is not owned by the
skb.

The fix is:

```text
f4c50a4034e6  xfrm: esp: avoid in-place decrypt on shared skb frags
```

It marks UDP datagram splice frags with `SKBFL_SHARED_FRAG`, matching what TCP
already does, and makes ESP input fall back to `skb_cow_data()` when that flag
is present. On a patched kernel the page cache is never the destination of the
decrypt.

## 2. Why `splice()` changes the ownership story

A file read normally copies bytes from the page cache into a userspace buffer.
`splice()` is different: it can put a reference to the page cache page itself
into a pipe. No copy is made.

The relevant path is:

```text
file page cache
    |
    | splice(file -> pipe)
    v
pipe_buffer { page = page cache page, offset, len }
    |
    | splice(pipe -> UDP socket)
    v
skb frag { page = page cache page, offset, len }
```

`MSG_SPLICE_PAGES` lets the UDP send path attach the pipe's pages directly to
the skb. The page is now a frag of a network packet. The kernel has not copied
it, and the page is still the file's page cache page.

On the receive side, the packet arrives on a UDP encapsulation socket with
`UDP_ENCAP_ESPINUDP`. The path is roughly:

```text
udp_rcv()
  xfrm4_udp_encap_rcv()
    xfrm_input()
      esp_input()
        if (!skb_cloned(skb) && !skb_has_frag_list(skb))
            goto skip_cow;          // <-- the bug
        ...
        crypto_aead_decrypt(req)    // src == dst, in place
```

The skb is uncloned. It is nonlinear, but it has frags rather than a
`frag_list`. So `esp_input()` takes the fast path. It builds a scatterlist
over the frags and asks the crypto layer to decrypt with source and destination
the same memory. The destination page is the file's page cache page.

The important consequences:

- no write permission on the file is needed;
- no copy-on-write happens;
- the page is not marked dirty;
- the file on disk does not change;
- every process that maps the file sees the modified page;
- a reboot, or dropping the page cache, restores the original contents.

This is why the bug is a page-cache write primitive rather than a normal
memory-corruption bug.

## 3. The write primitive: AES-CBC as an arbitrary 16-byte store

The Android port does not use the Linux PoC's ESP+ESN+authenc four-byte store.
It uses an AES-CBC transform created through Android's `IpSecManager`.

For one 16-byte block, let:

```text
K = the AES key we chose when creating the transform
C = the current 16 bytes of the file at the target offset
P = the 16 bytes we want the file to contain
IV = the initialization vector we put in the ESP packet
```

The kernel's CBC decryption of one block is:

```text
P_kernel = AES_DEC(K, C) XOR IV
```

We know `C` because we can read the file (or read it through the
`crash_dump64` bridge). We choose `IV`:

```text
IV = AES_DEC(K, C) XOR P
```

Then:

```text
P_kernel = AES_DEC(K, C) XOR (AES_DEC(K, C) XOR P)
         = P
```

So the ciphertext is the file's *current* content, and the IV is the value
that turns the kernel's decryption into our desired plaintext. The kernel
writes `P` into the page cache page.

The packet layout in `exp.c` is:

```text
SPI (4 bytes) | sequence (4 bytes) | IV (16 bytes) | ciphertext (16 bytes)
```

That is 40 bytes. The native binary sends it over a UDP socket bound to the
sender port that the transform expects. The Android framework installed the
SA; the kernel matches the SPI and decrypts the payload.

The app reads `C` in two ways:

- for system files (`crash_dump64`, `libc++.so`) it can `open()` and `pread()`;
- for `vendor_file` files it cannot open, so the `crash_dump64` helper reads
  the 16 bytes and passes them back through a pipe.

The write is 16 bytes per packet. A kernel module or a small shellcode blob is
therefore written in many 16-byte blocks. Each block is independent; each
packet carries its own IV.

### Why the Linux PoC looks different

The public Linux write-up describes a four-byte store in
`crypto_authenc_esn_decrypt()`. That variant uses ESP with ESN and an
authenticated encryption transform; the high-order sequence number is copied
to the end of the destination scatterlist, which can be a spliced page cache
page.

The Android port uses the same missing-COW bug, but a different store shape:
an in-place AES-CBC decryption gives a full 16-byte block. Same root cause,
different primitive width.

## 4. The Android chain

The chain in the DirtyFrag fork is:

```text
untrusted app
  |
  | 1. patch crash_dump64 page cache with splicehelper
  |    (borrow crash_dump SELinux domain -> vendor_file access)
  |
  | 2. patch a vendor library page cache with dfroot.ko
  |    (the module is now in a file vendor_modprobe can read)
  |
  | 3. patch /system/lib64/libc++.so with shellcode + branch
  |    (hook std::ostream::sentry)
  |
  | 4. create an orphan; init reaps it and calls the hooked function
  |    (shellcode runs in init, uid 0, tid 1)
  |
  | 5. shellcode execs /vendor/bin/insmod as vendor_modprobe
  |
  | 6. dfroot.ko: SELinux permissive, DEFEX patched, run bootstrap
  |
  | 7. bootstrap: ksud late-load -> kernelsu.ko -> manager -> root
```

### 4.1 `crash_dump64`: the SELinux bridge

`untrusted_app` can read system files but not `vendor_file` files. The
`crash_dump` SELinux domain can read `vendor_file`.

`crash_dump64` is a system binary that transitions into the `crash_dump`
domain when executed. The exploit replaces the first bytes of its page cache
with a small static ELF called `splicehelper`. The helper has its own ELF
header, program headers, `_start`, and raw syscalls. When the app executes
`crash_dump64`, the kernel parses the patched page cache and runs the helper
under the `crash_dump` label.

The helper has two modes:

- **read mode**: open the vendor file, read 16 bytes, write them to an
  inherited pipe;
- **splice mode**: open the vendor file, `splice()` a 16-byte page chunk into
  an inherited pipe.

The app never gets `vendor_file` permission. It inherits a pipe from a process
that does. That is the confused-deputy bridge.

`dfroot.ko` later calls `invalidate_inode_pages2()` on `crash_dump64`, dropping
the patched page cache so the real binary is restored from disk.

### 4.2 The vendor library: a container for `dfroot.ko`

The app cannot put a kernel module in `/data/local/tmp` and load it from
there. It needs a file that:

- the app can patch through the `crash_dump` bridge;
- `vendor_modprobe` can read when `insmod` runs.

The exploit tries:

```text
/vendor/lib64/libbinderdebug.so
/vendor/lib64/libstagefrighthw.so
/vendor/lib64/libstagefright_aidl_bufferpool2.so
```

It writes the correct `dfroot.ko` at offset 0. The vendor library becomes a
container. The page cache contains the module; the disk file is unchanged.

The KO is selected by Android release and kernel major/minor. A Galaxy A35
with Android 16 and a 5.15 kernel uses:

```text
ko/dfroot-android13-5.15.ko
```

The Android release token comes from `uname -r` (`android13`) and the kernel
version from the front of the release string (`5.15`).

### 4.3 `libc++.so`: hooking a C++ function

The app patches `/system/lib64/libc++.so` at the constructor:

```text
_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_
```

That is `std::ostream::sentry::sentry(std::ostream&)`. It is called at the
start of formatted C++ stream operations, including the logging path used by
`init`.

The ELF parser:

1. finds the executable `PT_LOAD`;
2. reads `.dynsym` / `.dynstr`;
3. resolves the symbol to a file offset;
4. skips a `PACIASP` / `PACIBSP` / `BTI` preamble if present;
5. finds a code cave, either the slack after the executable segment or a long
   run of zero bytes inside it.

The app writes:

- the shellcode into the code cave;
- a 4-byte ARM64 `B` branch at the hook site;
- a branch back at the end of the shellcode;
- a copy of the original first instruction.

The hook is transparent. When the constructor is called, the branch goes to
the shellcode. The shellcode eventually executes the original first
instruction and branches back to the second instruction of the constructor.

### 4.4 The shellcode and the `init` trigger

The shellcode in `libcxx.S` starts with two checks:

```asm
getuid() == 0
gettid() == 1
```

Only `init`'s main thread satisfies both. Every other process that maps
`libc++.so` returns through the trampoline.

If the checks pass, the shellcode:

1. creates `/dev/df` with `O_CREAT | O_EXCL | O_CLOEXEC` as a one-shot mutex;
2. saves the argument registers and `x30`;
3. clones a worker child;
4. the worker clones a grandchild;
5. the grandchild writes `u:r:vendor_modprobe:s0` to
   `/proc/self/attr/exec`;
6. the grandchild executes `/vendor/bin/insmod <ko_target>`;
7. the parent restores registers, executes the original instruction, and
   returns to `init`.

Why does `init` call the hooked function? The app double-forks. The
grandchild is reparented to PID 1. After a short sleep it exits. `init` reaps
it and its main thread calls the logging/stream path that uses
`std::ostream::sentry`. The hook fires in `init`, uid 0, tid 1.

This is why the exploit needs neither `ptrace` nor code injection into
`init`. It borrows `init` for a few instructions and gives it back.

### 4.5 `dfroot.ko`

`dfroot.ko` is loaded by `insmod` in the `vendor_modprobe` domain. Its init:

1. resolves `kallsyms_lookup_name` with a temporary kprobe;
2. resolves `aarch64_insn_patch_text`, `module_kallsyms_lookup_name`,
   `kern_path`, `invalidate_inode_pages2`, `path_put`, `selinux_state`,
   `task_defex_enforce`, `task_defex_user_exec`,
   `call_usermodehelper_setup`, and `call_usermodehelper_exec`;
3. drops the patched `crash_dump64` page cache;
4. writes `false` to the kernel's SELinux enforcement state;
5. patches Samsung DEFEX `task_defex_enforce` and
   `task_defex_user_exec` to return 0;
6. runs the bootstrap with `call_usermodehelper`;
7. returns `-ENODEV` so the kernel unloads it.

The DEFEX patch uses `aarch64_insn_patch_text()`, the kernel's own
instruction-patching helper, rather than a raw kernel-text write. It skips
`PACIASP`, `PACIBSP`, `BTI`, `BTI c`, `BTI j`, and `BTI jc`, then writes
`mov w0, #0` followed by `ret`, `retaa`, or `retab` depending on pointer
authentication support.

The module is not meant to stay resident. It has done its job once the
bootstrap is running.

### 4.6 `bootstrap`

`bootstrap` runs as UID 0 in kernel context. It reads:

```text
/data/user_de/0/df.root/shared_prefs/dfroot.xml
```

for:

- `su_manager`: the package name of the selected SU manager;
- `soft_reboot`: whether to run `ksud soft-reboot`;
- `disable_modules`: whether to disable all KernelSU modules before starting.

It then:

1. adopts the zygote environment by reading `/proc/<zygote>/environ` and
   `putenv()`ing each entry;
2. marks `super`, `misc`, `steady`, and `*_a` / `*_b` partitions read-only
   with `BLKROSET`;
3. optionally touches a `disable` file in every directory under
   `/data/adb/modules`;
4. forks a child that switches to `u:r:init:s0` while SELinux is permissive;
5. executes the staged `ksud late-load --package-name <manager>`;
6. if `soft_reboot` is set, waits for late-load to finish and runs
   `/data/adb/ksud soft-reboot` in `u:r:ksu:s0`.

The `disable_modules` step is why a fresh run can fail at `/dev/dfme1` when
`/data/adb/modules` does not exist: `opendir()` returns `NULL`, the function
returns `-1`, and the bootstrap aborts. With modules enabled, the step is
skipped.

### 4.7 `ksud late-load`

The app stages the manager's `libksud.so` as `/data/user_de/0/df.root/ksud`.
That file is the `ksud` executable renamed so Android packages it in the
native library directory. It contains embedded KernelSU modules for the
supported KMIs.

`ksud late-load`:

1. detects the KMI;
2. loads the matching embedded `kernelsu.ko`;
3. KernelSU's init sees `current->pid != 1`, so it sets
   `ksu_late_loaded = true`;
4. it skips kprobe hooks;
5. it applies SELinux rules, sets up `ksu_cred`, initializes the allowlist,
   installs syscall hooks, and starts the manager integration.

The manager then reports **Working — Jailbreak mode**. That means the
KernelSU driver is loaded, not that the boot image was patched.

## 5. What the app does

The DirtyFrag app is mostly a wrapper around the native chain.

`ExploitRunner.run()`:

- rejects a second run if `/dev/df` exists;
- finds the selected manager and requires `libksud.so`;
- stages `libksud.so` as `ksud` and `libbootstrap.so` as `bootstrap` in
  `/data/user_de/0/df.root`;
- opens a `UdpEncapsulationSocket`;
- allocates an SPI on `127.0.0.1`;
- generates a random 32-byte AES key;
- builds an `IpSecTransform` with `CRYPT_AES_CBC` and IPv4 encapsulation;
- executes `libdfroot.so` with the encap port, sender port, SPI, and key.

`libdfroot.so` is an executable named like a shared library because Android
only packages `lib*.so` into the executable native library directory.

The Java side reads the native process's stdout line by line and maps marker
files to a two-step progress bar.

| Marker | Meaning |
|---|---|
| `/dev/df` | shellcode ran in `init`; hook fired |
| `/dev/dfm0` | `dfroot.ko` init ran; bootstrap launched |
| `/dev/dfm1` | bootstrap read the prefs |
| `/dev/dfm2` | zygote environment cloned |
| `/dev/dfm3` | partitions set read-only |
| `/dev/dfm4` | disabling KernelSU modules |
| `/dev/dfm5` | starting the SU daemon |
| `/dev/dfm6` | `ksud` exited successfully |
| `/dev/dfme0` | reading prefs failed |
| `/dev/dfme1` | disabling modules failed |
| `/dev/dfme2` | `ksud` returned nonzero |
| `/dev/dfmw0` | zygote env clone failed (warning) |
| `/dev/dfmw1` | set-partitions-ro failed (warning) |

The app checks `/dev/df` at the end and calls that "Rooted". That marker really
means "the init hook fired", not "KernelSU is fully usable". The manager's
status is the authoritative check.

## 6. Why a full reboot is clean

After a normal full reboot:

- `/dev/df` and all `/dev/dfm*` markers are gone, because `/dev` is tmpfs;
- `dfroot.ko` is already unloaded;
- the KernelSU LKM loaded by `ksud late-load` is gone;
- SELinux is enforcing again;
- the page-cache patches are gone;
- the disk files were never modified.

What remains on disk:

- the DirtyFrag app;
- the KernelSU manager app;
- `/data/adb/ksud`, `/data/adb/modules`, and related files if `ksud`
  installed them;
- any KernelSU modules you installed.

Those files are inert without the KernelSU driver. They do not re-root the
device by themselves.

Things that can re-root it after a reboot:

- **Autorun** in DirtyFrag: the `BootReceiver` runs the exploit at boot;
- **Auto reboot**: a soft reboot, not a clean unroot;
- **Auto jailbreak** in the KernelSU manager: uses Magica at boot.

A full reboot with those off is the clean state.

## 7. Why `su` is not the same as root in late-load

The manager can say "Working" while `/system/bin/su` fails.

The traditional `/system/bin/su` path is a compatibility shim. It relies on a
KernelSU kernel hook that redirects an exec of `/system/bin/su` to `ksud`. In
late-load, kprobe hooks are skipped, so that redirect may not exist. The path
is a ghost: `ls` cannot see it, and executing it returns `ENOENT`.

The manager can still grant root through its own fd/ioctl interface, which is
why apps using the KernelSU API work while a Termux `su` wrapper does not.

That is why the practical workarounds are:

- a KernelSU module whose `action.sh` / `service.sh` runs as root;
- USB ADB with a root `adbd` (Magica / `adb root`);
- a manager build where `sucompat` works in late-load.

None of those change the exploit itself. They work around the fact that `su`
is not the root interface in this late-load setup.

## Hands-on

Read the fix before reading the exploit:

```sh
git show f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4
```

Then find the fast path in a vulnerable tree:

```sh
grep -n "skb_cow_data\|skb_has_frag_list\|skip_cow" net/ipv4/esp4.c
grep -n "SKBFL_SHARED_FRAG\|MSG_SPLICE_PAGES" net/ipv4/ip_output.c net/ipv4/esp4.c
```

On an Android target, compare:

```sh
uname -r
getprop ro.build.version.release
```

and check whether the kernel has the fix. If it does, the page-cache write
will not happen and a DirtyFrag-style chain will fail at its first
verification step.

## Checkpoint

1. Why does `splice(file -> pipe -> UDP)` put a page cache page into an skb
   frag instead of copying it?
2. Why is `skb_cow_data()` the correct fix, and what does
   `SKBFL_SHARED_FRAG` change?
3. Why is the AES-CBC IV enough to choose the plaintext, even though the
   attacker does not know the file's write permission?
4. Why can the app patch `crash_dump64` but not read a `vendor_file` directly?
5. Why does the shellcode check both `getuid() == 0` and `gettid() == 1`?
6. Why does `dfroot.ko` return `-ENODEV` instead of staying loaded?
7. Why can a full reboot clear root while a soft reboot may not?
8. Why can KernelSU say "Working" while `/system/bin/su` returns `ENOENT`?
