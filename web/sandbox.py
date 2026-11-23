"""
sandbox.py - run compilers and untrusted programs with hard limits.

Every run:
  * uses an argument list (never shell=True),
  * gets a wall-clock timeout (the whole process group is killed),
  * gets rlimits: CPU time, file size, open files, process count and
    (for non-ASan programs) address space,
  * runs in its own new user + network namespace when the kernel allows it
    (`unshare --user --net`): the program sees itself as "nobody" and has
    no network interfaces except a down loopback,
  * drops to "nobody" first if the server itself was started as root,
  * writes stdout+stderr to a file inside the temp directory, so a program
    that prints forever is stopped by RLIMIT_FSIZE instead of filling
    memory; only the first MAX_OUTPUT bytes are returned.

The caller creates the temp directory with `temp_workdir()` and it is
deleted when the `with` block ends.
"""
import contextlib
import os
import pwd
import resource
import shutil
import signal
import subprocess
import tempfile
import time

TIMEOUT_S = 5                  # wall clock per run
CPU_S = 5                      # CPU seconds per run
FSIZE_BYTES = 1 * 1024 * 1024  # largest file a run may write
MEM_BYTES = 256 * 1024 * 1024  # address space (non-ASan programs only)
NOFILE = 64
EXTRA_PROCS = 32               # processes allowed on top of current count
MAX_OUTPUT = 64 * 1024         # bytes of output returned to the browser

# ASan reserves terabytes of *virtual* shadow memory, so RLIMIT_AS cannot be
# used for it; its own RSS / malloc limits are used instead.
ASAN_OPTIONS = ("detect_leaks=1:hard_rss_limit_mb=256:malloc_limit_mb=256:"
                "allocator_may_return_null=0:abort_on_error=0:color=never")
UBSAN_OPTIONS = "print_stacktrace=1:color=never"


def _probe_unshare():
    exe = shutil.which("unshare")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "--user", "--net", "--", "true"],
                           capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return [exe, "--user", "--net", "--"] if r.returncode == 0 else None


UNSHARE = _probe_unshare()


def _user_process_count():
    """Threads owned by this user: RLIMIT_NPROC counts threads, not just
    processes, so the limit is set relative to this number."""
    uid = os.getuid()
    n = 0
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                if os.stat(f"/proc/{d}").st_uid == uid:
                    n += len(os.listdir(f"/proc/{d}/task"))
            except OSError:
                pass
    return n


def _nobody():
    try:
        pw = pwd.getpwnam("nobody")
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        return 65534, 65534


@contextlib.contextmanager
def temp_workdir():
    path = tempfile.mkdtemp(prefix="svp-web-")
    os.chmod(path, 0o755)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def run(argv, workdir, stdin=b"", cwd=None, asan=False, timeout=TIMEOUT_S,
        cpu=CPU_S, limit_memory=True):
    """Run argv with limits. Returns a dict with rc, output, timed_out,
    truncated, signal and duration."""
    nproc = _user_process_count() + EXTRA_PROCS
    as_root = os.geteuid() == 0
    uid, gid = _nobody()

    def preexec():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))  # SIGXCPU, then SIGKILL
        resource.setrlimit(resource.RLIMIT_FSIZE, (FSIZE_BYTES, FSIZE_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (NOFILE, NOFILE))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if limit_memory and not asan:
            resource.setrlimit(resource.RLIMIT_AS, (MEM_BYTES, MEM_BYTES))
        if as_root:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
        # Set last: when running as root this is checked against "nobody".
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))

    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HOME": workdir,
        "TMPDIR": workdir,
        "ASAN_OPTIONS": ASAN_OPTIONS,
        "UBSAN_OPTIONS": UBSAN_OPTIONS,
    }
    full = (UNSHARE or []) + list(argv)
    in_path = os.path.join(workdir, ".stdin")
    out_path = os.path.join(workdir, ".output")
    with open(in_path, "wb") as f:
        f.write(stdin)

    timed_out = False
    start = time.monotonic()
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        proc = subprocess.Popen(full, stdin=fin, stdout=fout,
                                stderr=subprocess.STDOUT, cwd=cwd or workdir,
                                env=env, preexec_fn=preexec, close_fds=True)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    duration = time.monotonic() - start

    with open(out_path, "rb") as f:
        data = f.read(MAX_OUTPUT + 1)
    truncated = len(data) > MAX_OUTPUT
    text = data[:MAX_OUTPUT].decode("utf-8", errors="replace")
    os.remove(out_path)
    os.remove(in_path)

    rc = proc.returncode
    sig = None
    if rc is not None and rc < 0:
        sig = signal.Signals(-rc).name
        rc = 128 - rc   # same convention as the shell (SIGSEGV -> 139)
    # Which sandbox limit stopped the program, if any.
    limit = None
    if timed_out or sig == "SIGXCPU" or (sig == "SIGKILL" and duration >= cpu):
        limit = "time"
    elif sig == "SIGXFSZ":
        limit = "output"
    return {
        "limit": limit,
        "rc": rc,
        "signal": sig,
        "timed_out": timed_out,
        "output": text,
        "truncated": truncated,
        "duration": round(duration, 3),
    }


def describe_limits():
    return {
        "timeout_s": TIMEOUT_S,
        "cpu_s": CPU_S,
        "max_file_bytes": FSIZE_BYTES,
        "memory_mb": MEM_BYTES // (1024 * 1024),
        "max_output_bytes": MAX_OUTPUT,
        "network_isolated": UNSHARE is not None,
        "runs_as": "nobody (user namespace)" if UNSHARE else
                   ("nobody" if os.geteuid() == 0 else pwd.getpwuid(os.getuid()).pw_name),
    }
