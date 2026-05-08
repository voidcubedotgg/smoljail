use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{
    ForkResult, Gid, Pid, Uid, chdir, execve, fork, pivot_root, setgid, setgroups, setpgid, setsid,
    setuid,
};

const SMOLVM_SOCKET: &str = "unix:///var/run/smolvm.sock";

/// Seconds to wait after sending SIGTERM to the jailed child before escalating to SIGKILL.
const SHUTDOWN_GRACE_SECS: u32 = 5;

/// Set by the parent after fork; read by signal handlers to forward signals to the child.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// Read-only host paths that get bind-mounted into the jail at the same path.
const SYSTEM_LIB_PATHS: &[&str] = &["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

/// Host device files that get bind-mounted into the jail (read-write).
const DEVICE_NODES: &[&str] = &["/dev/kvm", "/dev/null", "/dev/urandom", "/dev/zero"];

#[derive(Parser, Debug)]
#[command(
    name = "smoljail",
    version,
    author = "Petr Václavek (Rispy) <petr@vaclavek.cloud>",
    about = "Wraps smolvm in a mount-namespace + Landlock sandbox to shrink microVM-escape blast radius."
)]
struct Cli {
    /// Unique identifier for the jail (used as subdirectory name).
    #[arg(long)]
    id: String,

    /// Path to the smolvm wrapper script or smolvm-bin ELF.
    #[arg(long = "smolvm_bin", value_name = "FILE")]
    smolvm_bin: PathBuf,

    /// Path to smolvm's data directory on the host (contains agent-rootfs/, server/, init.krun).
    #[arg(long = "smolvm_data_dir", value_name = "PATH")]
    smolvm_data_dir: PathBuf,

    /// Numeric UID to drop to before exec.
    #[arg(long, value_name = "UID")]
    uid: u32,

    /// Numeric GID to drop to before exec.
    #[arg(long, value_name = "GID")]
    gid: u32,

    /// Base directory under which `<id>/root` is created (used as mount-point staging).
    #[arg(
        long = "chroot_base_dir",
        value_name = "PATH",
        default_value = "/var/lib/smolvm"
    )]
    chroot_base_dir: PathBuf,

    /// Background the supervisor (POC: stdio is inherited; use shell redirect or systemd).
    #[arg(short, long)]
    daemon: bool,
}

/// Resolved host-side inputs after CLI parsing.
struct HostLayout {
    /// Directory containing `smolvm-bin` and `lib/` (parent of the ELF).
    smolvm_install_dir: PathBuf,
    /// Host data directory (contains agent-rootfs/, etc.).
    data_dir: PathBuf,
    /// On-disk staging root (mountpoints).
    chroot_root: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !Uid::effective().is_root() {
        bail!("smoljail must run as root (needs CAP_SYS_ADMIN for mount/pivot_root, plus setuid)");
    }

    if cli.daemon {
        daemonize().context("daemonize")?;
    }

    let layout = resolve_layout(&cli).context("resolving host layout")?;
    prepare_staging(&layout).context("preparing staging mountpoints")?;

    let exit_code = run_jailed(&layout, cli.uid, cli.gid).context("running jailed smolvm")?;
    std::process::exit(exit_code);
}

fn daemonize() -> Result<()> {
    match unsafe { fork() }.context("fork for daemonize")? {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {
            setsid().context("setsid")?;
            chdir("/").context("chdir /")?;
            Ok(())
        }
    }
}

fn resolve_layout(cli: &Cli) -> Result<HostLayout> {
    // If --smolvm_bin points at the bash wrapper, use the sibling smolvm-bin.
    let provided = cli
        .smolvm_bin
        .canonicalize()
        .with_context(|| format!("canonicalizing --smolvm_bin {}", cli.smolvm_bin.display()))?;
    let smolvm_elf = if is_shell_script(&provided)? {
        let parent = provided
            .parent()
            .ok_or_else(|| anyhow!("--smolvm_bin {} has no parent dir", provided.display()))?;
        let candidate = parent.join("smolvm-bin");
        if !candidate.is_file() {
            bail!(
                "--smolvm_bin points at a wrapper script but sibling smolvm-bin not found at {}",
                candidate.display()
            );
        }
        candidate
    } else {
        provided
    };

    let smolvm_install_dir = smolvm_elf
        .parent()
        .ok_or_else(|| anyhow!("smolvm ELF has no parent dir"))?
        .to_path_buf();

    let data_dir = cli.smolvm_data_dir.canonicalize().with_context(|| {
        format!(
            "canonicalizing --smolvm_data_dir {}",
            cli.smolvm_data_dir.display()
        )
    })?;
    if !data_dir.is_dir() {
        bail!(
            "--smolvm_data_dir {} is not a directory",
            data_dir.display()
        );
    }

    let chroot_root = cli.chroot_base_dir.join(&cli.id).join("root");

    if !smolvm_elf.is_file() {
        bail!("resolved smolvm ELF {} is not a file", smolvm_elf.display());
    }

    Ok(HostLayout {
        smolvm_install_dir,
        data_dir,
        chroot_root,
    })
}

fn is_shell_script(p: &Path) -> Result<bool> {
    let mut buf = [0u8; 2];
    let mut f = fs::File::open(p).with_context(|| format!("open {}", p.display()))?;
    use std::io::Read;
    let n = f
        .read(&mut buf)
        .with_context(|| format!("read {}", p.display()))?;
    Ok(n == 2 && &buf == b"#!")
}

/// Build the staging tree on host disk: empty directories that will become mount points
/// inside the child's namespace. Nothing is copied.
fn prepare_staging(layout: &HostLayout) -> Result<()> {
    let root = &layout.chroot_root;
    let dirs = [
        "",
        "opt/smolvm",
        "var/lib/smolvm",
        "var/run",
        "var/cache/smolvm",
        "tmp",
        "proc",
        "dev",
        "lib",
        "lib64",
        "usr/lib",
        "usr/lib64",
    ];
    for d in dirs {
        let p = root.join(d);
        fs::create_dir_all(&p).with_context(|| format!("mkdir {}", p.display()))?;
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).context("chmod chroot root")?;

    // Empty placeholder files for device-node bind mounts.
    for dev in DEVICE_NODES {
        let p = root.join(dev.trim_start_matches('/'));
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        }
        if !p.exists() {
            fs::File::create(&p).with_context(|| format!("touch {}", p.display()))?;
        }
    }

    Ok(())
}

fn run_jailed(layout: &HostLayout, uid: u32, gid: u32) -> Result<i32> {
    // Pre-build all CStrings the child will need (post-fork allocations are unsafe).
    let chroot_cstr = path_to_cstring(&layout.chroot_root)?;
    let install_src = path_to_cstring(&layout.smolvm_install_dir)?;
    let data_src = path_to_cstring(&layout.data_dir)?;

    let bin_cstr = CString::new("/opt/smolvm/smolvm-bin").unwrap();
    let argv: [CString; 6] = [
        CString::new("smolvm-bin").unwrap(),
        CString::new("serve").unwrap(),
        CString::new("start").unwrap(),
        CString::new("-l").unwrap(),
        CString::new(SMOLVM_SOCKET).unwrap(),
        CString::new("--json-logs").unwrap(),
    ];
    let envp: [CString; 4] = [
        CString::new("LD_LIBRARY_PATH=/opt/smolvm/lib").unwrap(),
        CString::new("XDG_DATA_HOME=/var/lib").unwrap(),
        CString::new("XDG_CACHE_HOME=/var/cache").unwrap(),
        CString::new("PATH=/opt/smolvm:/usr/bin:/bin").unwrap(),
    ];

    match unsafe { fork() }.context("fork for jailed child")? {
        ForkResult::Parent { child } => {
            CHILD_PID.store(child.as_raw(), Ordering::SeqCst);
            install_supervisor_signal_handlers().context("installing signal handlers")?;
            wait_child(child).context("waiting on child")
        }
        ForkResult::Child => {
            child_setup_and_exec(
                &chroot_cstr,
                &install_src,
                &data_src,
                &bin_cstr,
                &argv,
                &envp,
                uid,
                gid,
            );
        }
    }
}

extern "C" fn forward_term_handler(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // Forward SIGTERM and arm an alarm to escalate to SIGKILL if the child
        // doesn't exit gracefully within the grace period.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
            libc::alarm(SHUTDOWN_GRACE_SECS);
        }
    }
}

extern "C" fn force_kill_handler(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

fn install_supervisor_signal_handlers() -> Result<()> {
    unsafe fn install(signum: libc::c_int, handler: extern "C" fn(libc::c_int)) -> Result<()> {
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = handler as usize;
        unsafe { libc::sigemptyset(&mut sa.sa_mask) };
        sa.sa_flags = 0;
        let rc = unsafe { libc::sigaction(signum, &sa, std::ptr::null_mut()) };
        if rc != 0 {
            bail!(
                "sigaction({signum}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }
    unsafe {
        install(libc::SIGINT, forward_term_handler)?;
        install(libc::SIGTERM, forward_term_handler)?;
        install(libc::SIGALRM, force_kill_handler)?;
    }
    Ok(())
}

fn wait_child(child: Pid) -> Result<i32> {
    loop {
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Ok(other) => bail!("unexpected wait status: {other:?}"),
            // Signal handler ran (e.g. SIGINT/SIGTERM/SIGALRM). It may have
            // forwarded a signal to the child; loop and keep waiting.
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(anyhow!("waitpid: {e}")),
        }
    }
}

/// Runs in the forked child. On any failure, writes a tag to stderr and `_exit`s.
#[allow(clippy::too_many_arguments)]
fn child_setup_and_exec(
    chroot_path: &CStr,
    smolvm_install_src: &CStr,
    data_src: &CStr,
    bin: &CStr,
    argv: &[CString],
    envp: &[CString],
    uid: u32,
    gid: u32,
) -> ! {
    macro_rules! die {
        ($tag:expr, $err:expr) => {{
            let _ = write_stderr($tag, &format!("{:?}", $err));
            unsafe { libc::_exit(127) };
        }};
    }

    if let Err(e) = close_inherited_fds() {
        die!("close_fds", e);
    }

    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        die!("no_new_privs", std::io::Error::last_os_error());
    }

    if let Err(e) = setup_mount_ns(chroot_path, smolvm_install_src, data_src, uid, gid) {
        die!("mount_ns", e);
    }

    if let Err(e) = apply_landlock() {
        die!("landlock", e);
    }

    drop_bounding_caps();

    if let Err(e) = setgroups(&[]) {
        die!("setgroups", e);
    }
    if let Err(e) = setgid(Gid::from_raw(gid)) {
        die!("setgid", e);
    }
    if let Err(e) = setuid(Uid::from_raw(uid)) {
        die!("setuid", e);
    }

    // PDEATHSIG must be set AFTER the credential change: the kernel clears it
    // across uid/gid transitions (so a setuid'd process can't inherit a
    // privileged ancestor's death signal).
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        die!("pdeathsig", std::io::Error::last_os_error());
    }

    if let Err(e) = setpgid(Pid::from_raw(0), Pid::from_raw(0)) {
        die!("setpgid", e);
    }

    let argv_refs: Vec<&CStr> = argv.iter().map(|c| c.as_c_str()).collect();
    let envp_refs: Vec<&CStr> = envp.iter().map(|c| c.as_c_str()).collect();
    match execve(bin, &argv_refs, &envp_refs) {
        Ok(_) => unreachable!(),
        Err(e) => die!("execve", e),
    }
}

fn setup_mount_ns(
    chroot_path: &CStr,
    smolvm_install_src: &CStr,
    data_src: &CStr,
    uid: u32,
    gid: u32,
) -> Result<()> {
    let chroot = cstr_to_path(chroot_path);

    unshare(CloneFlags::CLONE_NEWNS).context("unshare CLONE_NEWNS")?;

    // Make all mounts in this namespace private so our bind-mounts don't propagate
    // back to the host, and host changes don't leak in.
    mount::<str, _, str, str>(
        Some("none"),
        "/",
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )
    .context("mount / private,rec")?;

    // pivot_root requires the new root to be a mount point. Bind-mount it onto itself.
    mount::<_, _, str, str>(
        Some(chroot),
        chroot,
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    )
    .context("bind chroot onto itself")?;

    // Bind read-only: smolvm install dir → /opt/smolvm
    bind_ro(cstr_to_path(smolvm_install_src), &chroot.join("opt/smolvm"))?;

    // Bind read-only: data dir → /var/lib/smolvm
    let data_host = cstr_to_path(data_src);
    bind_ro(data_host, &chroot.join("var/lib/smolvm"))?;

    // Overlay smolvm's writable server/ subdir (sqlite + redb live here).
    let server_src = data_host.join("server");
    if server_src.is_dir() {
        bind_rw(&server_src, &chroot.join("var/lib/smolvm/server"))?;
    }

    // Bind read-only: system library trees
    for src in SYSTEM_LIB_PATHS {
        let target = chroot.join(src.trim_start_matches('/'));
        if !Path::new(src).exists() {
            continue;
        }
        bind_ro(Path::new(src), &target)?;
    }

    // Bind read-write: device files
    for dev in DEVICE_NODES {
        let target = chroot.join(dev.trim_start_matches('/'));
        if !Path::new(dev).exists() {
            // /dev/kvm may be absent — fail loudly there, others can be skipped silently.
            if *dev == "/dev/kvm" {
                bail!("/dev/kvm not present on host (KVM not enabled?)");
            }
            continue;
        }
        bind_rw(Path::new(dev), &target)?;
    }

    // tmpfs at /tmp
    mount(
        Some("tmpfs"),
        &chroot.join("tmp"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777"),
    )
    .context("mount tmpfs /tmp")?;

    // tmpfs at /var/run, owned by target uid/gid so smolvm can create its socket.
    let var_run_opts = format!("mode=755,uid={uid},gid={gid}");
    mount(
        Some("tmpfs"),
        &chroot.join("var/run"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(var_run_opts.as_str()),
    )
    .context("mount tmpfs /var/run")?;

    // tmpfs at /var/cache/smolvm so smolvm has a writable cache (XDG_CACHE_HOME).
    let cache_opts = format!("mode=755,uid={uid},gid={gid}");
    mount(
        Some("tmpfs"),
        &chroot.join("var/cache/smolvm"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(cache_opts.as_str()),
    )
    .context("mount tmpfs /var/cache/smolvm")?;

    // /proc — fresh procfs.
    mount::<str, _, str, str>(
        Some("proc"),
        &chroot.join("proc"),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None,
    )
    .context("mount proc")?;

    // pivot_root: move new root to /, old root to /.old_root, then unmount old.
    let old_root = chroot.join(".old_root");
    fs::create_dir_all(&old_root).context("mkdir .old_root")?;
    pivot_root(chroot, &old_root).context("pivot_root")?;
    chdir("/").context("chdir / post-pivot")?;
    umount2("/.old_root", MntFlags::MNT_DETACH).context("umount /.old_root")?;
    fs::remove_dir("/.old_root").context("rmdir /.old_root")?;

    Ok(())
}

fn bind_ro(src: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target.parent().unwrap_or(target))
        .with_context(|| format!("mkdir parent of {}", target.display()))?;
    if src.is_dir() && !target.exists() {
        fs::create_dir_all(target).with_context(|| format!("mkdir {}", target.display()))?;
    }
    mount::<_, _, str, str>(
        Some(src),
        target,
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    )
    .with_context(|| format!("bind {} -> {}", src.display(), target.display()))?;
    // Bind mounts ignore most flags on the initial mount; remount to enforce read-only + nosuid.
    mount::<str, _, str, str>(
        Some("none"),
        target,
        None,
        MsFlags::MS_REMOUNT
            | MsFlags::MS_BIND
            | MsFlags::MS_REC
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID,
        None,
    )
    .with_context(|| format!("remount RO {}", target.display()))?;
    Ok(())
}

fn bind_rw(src: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    if !target.exists() {
        if src.is_dir() {
            fs::create_dir_all(target).with_context(|| format!("mkdir {}", target.display()))?;
        } else {
            fs::File::create(target).with_context(|| format!("touch {}", target.display()))?;
        }
    }
    mount::<_, _, str, str>(Some(src), target, None, MsFlags::MS_BIND, None)
        .with_context(|| format!("bind {} -> {}", src.display(), target.display()))?;
    Ok(())
}

fn cstr_to_path(c: &CStr) -> &Path {
    Path::new(OsStr_from_bytes(c.to_bytes()))
}

#[allow(non_snake_case)]
fn OsStr_from_bytes(b: &[u8]) -> &std::ffi::OsStr {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(b)
}

fn close_inherited_fds() -> Result<()> {
    let dir = fs::read_dir("/proc/self/fd").context("open /proc/self/fd")?;
    let mut to_close = Vec::new();
    for entry in dir {
        let entry = entry?;
        let name = entry.file_name();
        let Some(s) = name.to_str() else { continue };
        let Ok(fd) = s.parse::<i32>() else { continue };
        if fd > 2 {
            to_close.push(fd);
        }
    }
    for fd in to_close {
        unsafe { libc::close(fd) };
    }
    Ok(())
}

fn apply_landlock() -> Result<()> {
    let floor = ABI::V2;
    let abi = ABI::V6;

    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(floor))?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .create()?;

    let read = AccessFs::from_read(abi);
    let all = AccessFs::from_all(abi);

    let ruleset = ruleset
        .add_rule(PathBeneath::new(
            PathFd::new("/opt/smolvm").context("open /opt/smolvm")?,
            read,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/var/lib/smolvm").context("open /var/lib/smolvm")?,
            read,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/lib").context("open /lib")?,
            read,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/lib64").context("open /lib64")?,
            read,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/usr/lib").context("open /usr/lib")?,
            read,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/var/run").context("open /var/run")?,
            all,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/tmp").context("open /tmp")?,
            all,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/var/cache").context("open /var/cache")?,
            all,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/var/lib/smolvm/server").context("open server")?,
            all,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/kvm").context("open /dev/kvm")?,
            all,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/null").context("open /dev/null")?,
            all,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/urandom").context("open /dev/urandom")?,
            all,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/zero").context("open /dev/zero")?,
            all,
        ))?;

    let status = ruleset.restrict_self().context("landlock restrict_self")?;
    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("landlock ruleset not enforced");
    }
    Ok(())
}

fn drop_bounding_caps() {
    let last = read_cap_last_cap().unwrap_or(40);
    for cap in 0..=last {
        unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
    }
}

fn read_cap_last_cap() -> Option<u32> {
    fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

fn path_to_cstring(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_bytes()).context("path contains NUL byte")
}

fn write_stderr(tag: &str, detail: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = std::io::stderr().lock();
    writeln!(out, "smoljail child: {tag}: {detail}")
}
