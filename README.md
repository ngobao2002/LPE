# lpe/ -- macOS WebDAV stale-heap info-leak PoC (stage 0)

Stage 0 of a macOS kernel LPE research chain, after the Black Hat USA 2026
talk by Blazakis/Calif. Target: macOS 26.4.1 (25E253), Apple silicon.

For the author's own security research on their own machines. This stage is
an information leak only: no kernel R/W, no post-exploitation.

## The bug

`webdav_read_bytes()` in the webdavfs kext
(`webdavfs/webdav_fs.kextproj/webdav_fs.kmodproj/webdav_vnops.c:1945,1973,1999`
in this repo's older source drop; same structure on the target):

1. `MALLOC(buffer, void*, (uint32_t)MAX_READ, M_TEMP, M_WAITOK)` -- no
   `M_ZERO`. `MAX_READ` is ~19.7 MB, so this is `kalloc_large`: fresh,
   unzeroed, recycled pages.
2. It asks the userland mount daemon for `request_read.count` bytes over a
   socket with `MSG_WAITALL` (`sock_receive(..., MSG_WAITALL, &iolen)` at
   `webdav_vnops.c:379`). `sock_receive`/`soreceive` may legally return a
   SHORT count with `error == 0` when the peer closes the connection.
3. The returned length (`iolen`) is never checked:
   `uiomove(buffer, request_read.count, a_uio)` copies the full requested
   count to userspace -- so `count - received` bytes of stale, unzeroed
   kernel heap land in the reader's buffer.

Notes:

* `webdav_read_bytes` rejects reads at `offset == 0` (`EINVAL`), so the PoC
  always reads at a non-zero offset.
* The userland daemon (`mount.tproj/webdav_network.c network_read`) only
  clamps over-long replies and never validates a short 206 response;
  `translate_status_to_error` maps all 2xx to success. A malicious server
  that answers a ranged GET with a well-formed but short `206 Partial
  Content` and then closes makes the daemon forward the short reply and
  close the per-request socket to the kernel -- producing the short
  `sock_receive`.

## Layout

```
server/webdav_server.py   malicious WebDAV server (stdlib only)
src/leak.c                mount + pread + scan leak primitive
src/spray.c, src/spray.h  heap grooming: mach_msg OOL-ports spray,
                          ICMPv6 raw-socket (inpcb) spray
Makefile                  make leak / make run-leak
```

## Usage

Build (host: macOS arm64, `/usr/bin/clang`):

```sh
cd lpe
make leak
```

Unit-test the server without mounting:

```sh
python3 server/webdav_server.py --port 8080 --body-len 0 &
curl -i -X PROPFIND -H 'Depth: 1' http://127.0.0.1:8080/
curl -i -H 'Range: bytes=4096-8191' http://127.0.0.1:8080/poc.bin   # short 206
```

Run the full PoC (mounts a WebDAV share; raw-socket spray needs root):

```sh
python3 server/webdav_server.py --port 8080 --body-len 0 &
sudo bin/leak --server http://127.0.0.1:8080 \
     --size 8M --offset 4096 --spray ports --count 512 --descs 16383
```

or in one shot:

```sh
sudo make run-leak BODY_LEN=0 LEAK_ARGS="--size 8M --offset 4096 --spray ports"
```

`leak` CLI:

| flag       | meaning                                              | default                |
|------------|------------------------------------------------------|------------------------|
| `--server` | malicious server URL                                 | `http://127.0.0.1:8080`|
| `--mount`  | mountpoint dir                                       | `/tmp/lpe-webdav-mnt`  |
| `--size`   | pread size (`K`/`M` suffix ok)                       | `4M`                   |
| `--offset` | pread offset, must be non-zero                       | `4096`                 |
| `--spray`  | `ports` / `inpcb` / `none`                           | `none`                 |
| `--count`  | spray units: mach messages or raw sockets            | `512`                  |
| `--descs`  | OOL port descriptors per message                     | `16383`                |

Constraints from the setup: `offset + size <= 16 MiB` (the advertised file
size) and `size <= MAX_READ` (~19.7 MB) per kernel read request.

## How the sprays map to the leak

* **OOL-ports spray** (`--spray ports`): each queued mach message carries one
  OOL-ports descriptor with `--descs` descriptors; the kernel copyin allocates
  a `descs*8`-byte `kalloc_large` array of `ipc_port` pointers (16383
  descriptors -> 131064 bytes, matching the slides). Every descriptor
  references one "marker" port, so each freed array is full of copies of a
  single kernel pointer. `leak` sprays, immediately frees (destroying the
  queue holders releases the arrays), then reads: reclaimed pages show up as
  many copies of one pointer-valued qword. The scanner reports the modal
  kernel-pointer value and its frequency -- the number of recovered sprayed
  port-pointer copies.
* **ICMPv6 spray** (`--spray inpcb`): opens `--count` `AF_INET6`/`SOCK_RAW`/
  `IPPROTO_ICMPV6` sockets (needs root) to grow the raw-PCB `inpcb` pointer
  table before the leak.
