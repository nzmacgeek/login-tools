# Agent Instructions for all BlueyOS userspace packages

> These instructions apply to **every** Copilot coding agent working in this
> repository.  Read this file before starting any task.

---

## 1. Ecosystem overview — look at ALL nzmacgeek repos

BlueyOS is a multi-repo operating system project.  Before making any change
you must check whether the change touches an interface that spans multiple
repos and consult the relevant repo:

| Repo | Role | Key files |
|------|------|-----------|
| **nzmacgeek/biscuits** | i386 kernel, VFS, syscalls, drivers | `kernel/`, `drivers/`, `fs/`, `net/` |
| **nzmacgeek/claw** | PID 1 init daemon (service manager) | `src/claw/main.c`, `src/core/service/supervisor.c` |
| **nzmacgeek/matey** | getty / login prompt | `matey.c` |
| **nzmacgeek/walkies** | Network configuration tool (netctl) | see WALKIES_PROMPT.md in biscuits |
| **nzmacgeek/yap** | Syslog daemon / log rotation | `yap.c` (or equivalent) |
| **nzmacgeek/dimsim** | Package manager / firstboot scripts | `cmd/`, `internal/`, `template/` |
| **nzmacgeek/musl-blueyos** | musl libc patched for BlueyOS syscalls | `arch/i386/`, `src/` |
| **nzmacgeek/blueyos-bash** | Bash 5 patched for BlueyOS | `configure.ac`, patches |

**When working on a kernel syscall, always check musl-blueyos and blueyos-bash
to understand the caller expectations.**

---

## 2. Verbosity control — standard practice across all BlueyOS software

All userspace daemons must honour a `--verbose` / `-v` flag **and** the
`VERBOSE` environment variable (set by claw from the kernel `verbose=` arg):

```
VERBOSE=0  quiet (default) — errors + lifecycle events only
VERBOSE=1  info — detailed operational messages
VERBOSE=2  debug — all trace messages
```

**Retrofit rule:** when modifying any logging call in a userspace daemon,
check that the log level used is appropriate for the message content, and
add a verbosity guard if the message is debug-only.

---

## 3. Coding conventions

- Userspace daemons are C11 (`-std=gnu11`) with musl libc, statically linked.
- 4-space indentation.  No tabs except in Makefiles.
- Always add a corresponding entry in `docs/DEFECT_ANALYSIS.md` when you fix
  a defect that was catalogued there.

---

## 4. Versioning, packaging and installation

- All BlueyOS userspace software repos should have Makefile targets that build a dimsim package
- Build numbers are calculated based on the commit by which the target binaries are built from
- The build and version number should be accessible from all binaries and scripts using '--version'
- A target should be made available to install the package directly to the BlueyOS sysroot when building an image.
- Build using the correct architecture target. BlueyOS is currently i386 only so build that way, against musl-blueyos as a libc.

---

## 5. Repo memory hygiene

When you discover a new fact about the codebase that would help future agents,
call `store_memory` with:
- `subject`: short topic (e.g., "syscall implementation")
- `fact`: one-sentence statement
- `citations`: file:line where the fact is verified
- `reason`: why it matters for future tasks

Refresh existing memories you find to be accurate by storing them again (only
recent memories are kept).
