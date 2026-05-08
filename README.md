# Smoljail

The smoljail provide extra layer of security to smolvm on Linux machines.

IMPORTANT: This software is POC, still under active development, there might be breaking changes in future releases

### Features (v1)

- Builds a chroot at `<chroot_base>/<id>/root` and copies the smolvm binary into `<chroot>/bin/`
- Forks, applies `PR_SET_NO_NEW_PRIVS`, chroots, applies a Landlock filesystem ruleset, drops the capability bounding set, drops to the requested uid/gid, and execs `smolvm serve start -l unix:///var/run/smolvm.sock --json-logs`
- `PR_SET_PDEATHSIG(SIGKILL)` so the jailed smolvm dies if the supervisor dies
- Optional `-d/--daemon` (single fork + `setsid`; stdio is inherited — redirect via shell or run under systemd)

### Requirements (Host)

- Linux 5.19+ (Landlock ABI v2 is the hard floor; ABI v3+ features used opportunistically). [Supported distros](https://landlock.io/integrations/#linux-distributions)
- Run as root (needs CAP_SYS_CHROOT, chown, setuid). The jailed smolvm runs as the given `--uid`/`--gid`.
- Smolvm binary [Get it here]()

### Usage

```
sudo smoljail \
  --id vm100 \
  --smolvm_bin /usr/local/bin/smolvm \
  --uid 10000 \
  --gid 10000 \
  --chroot_base_dir /srv/smoljail \
  --daemon
```

### Not yet implemented (planned)

- Mount and network namespaces
- seccomp filters
- Cleanup of chroot dirs on exit
- PID file, structured log redirection
