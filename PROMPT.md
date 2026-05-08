We are building smoljail simple program thats going to shrink blast radius of exploits that cause escape from smolvm microvm (libkrun) into host.

### Program FLow:
1. Create chroot dir on host system default /var/lib/smolvm/<unique-id>/root
2. Copy smolvm binary into chroot dir root bin <chroot>/root/bin/
3. Prepare all other required directories for smolvm (This is doing to trial and error as I dont exactly what is required. Starting point for its /var/run, /tmp)
4. Start smolvm serve start -l unix:///var/run/smolvm.sock --json-logs (in landlock sandbox)
5. If user provide -d --daemon but process into running sandbox into background

### Example command 
smoljail \
  --id vm100 \
  --daemon
  --smolvm_bin /usr/local/bin/smolvm \
  --uid 10000 \
  --gid 10000 \
  --chroot_base_dir /srv/smoljail (Default /var/lib/smolvm)

### Open questions?
- What dirs are required for smolvm to function properly?
- Can we leverage netns (network namespaces)?