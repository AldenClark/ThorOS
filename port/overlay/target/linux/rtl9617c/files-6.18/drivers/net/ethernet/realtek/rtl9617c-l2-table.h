/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_L2_TABLE_H
#define RTL9617C_L2_TABLE_H

#include "rtl9617c-l2-format.h"
#include "rtl9617c-qm-deepq.h"

/* All callers share the FE/L2/PON owner mutex. indirect() submits a command
 * and waits for completion with a bounded timeout. A timeout is ambiguous:
 * retain the snapshot/resource ownership and close ingress until recovery.
 * The next caller must not alter any DATA word until ACCESS is idle. These
 * helpers intentionally provide no whole-table init/flush/replace-oldest.
 */
static inline int rtl_l2_io_valid(const struct rtl_dq_io *io)
{
	return io && io->read && io->write && io->indirect;
}

/* FDB and MAC limit windows share cpu_opt_mode. Learning is stopped by the
 * fabric owner for this mode lease. No mode or DATA write is allowed while
 * either window is busy, including a different late-completing operation.
 */
static inline int rtl_l2_fdb_mode_idle(const struct rtl_dq_io *io)
{
	if (!rtl_l2_io_valid(io))
		return -EINVAL;
	if ((io->read(io->context, RTL_L2_FDB_ACCESS) |
	     io->read(io->context, RTL_L2_FDB_LIMIT_ACCESS)) & RTL_L2_ACCESS_BUSY)
		return -EBUSY;
	if (!(io->read(io->context, RTL_L2_FDB_CONTROL) & RTL_L2_FDB_LEARN_DISABLE))
		return -EBUSY;
	return 0;
}

/* Owner-only recovery after an ambiguous limit command. The caller retains
 * the original global-mode snapshot. A successful idle observation, not a
 * timeout or a new caller's guess, permits returning its lease to CMD mode.
 */
static inline int rtl_l2_fdb_command_mode(const struct rtl_dq_io *io)
{
	unsigned int control;
	int ret = rtl_l2_fdb_mode_idle(io);

	if (ret)
		return ret;
	control = io->read(io->context, RTL_L2_FDB_CONTROL);
	io->write(io->context, RTL_L2_FDB_CONTROL, control | RTL_L2_FDB_CMD_MODE);
	io->read(io->context, RTL_L2_FDB_CONTROL);
	return 0;
}

static inline int rtl_l2_port_limit_access(const struct rtl_dq_io *io,
					unsigned int port, unsigned int *word,
					unsigned int write)
{
	unsigned int control, result = 0, request;
	int ret;

	if (!word || port >= RTL_L2_LOGICAL_PORTS || write > 1)
		return -EINVAL;
	ret = rtl_l2_fdb_mode_idle(io);
	if (ret)
		return ret;
	control = io->read(io->context, RTL_L2_FDB_CONTROL);
	if (!(control & RTL_L2_FDB_CMD_MODE))
		return -EOPNOTSUPP;
	io->write(io->context, RTL_L2_FDB_CONTROL, control & ~RTL_L2_FDB_CMD_MODE);
	io->read(io->context, RTL_L2_FDB_CONTROL);
	request = RTL_L2_ACCESS_BUSY | RTL_L2_FDB_LIMIT_SELECT | port;
	if (write) {
		io->write(io->context, RTL_L2_FDB_LIMIT_DATA, *word);
		request |= RTL_L2_ACCESS_WRITE;
	}
	ret = io->indirect(io->context, RTL_L2_FDB_LIMIT_ACCESS, request);
	if (ret)
		return ret; /* mode0 retained: timeout is not cancellation. */
	if (!write)
		result = io->read(io->context, RTL_L2_FDB_LIMIT_DATA);
	ret = rtl_l2_fdb_mode_idle(io);
	if (ret)
		return ret;
	io->write(io->context, RTL_L2_FDB_CONTROL, control);
	io->read(io->context, RTL_L2_FDB_CONTROL);
	if (!write)
		*word = result;
	return 0;
}

/* Raw words, including reserved bits: write a read snapshot with only the
 * low RTL_L2_FDB_LIMIT_MAX bits replaced. 0 is a real zero-learning limit,
 * not "unlimited". No count-init, decrement, or whole-FDB flush is exposed.
 */
static inline int rtl_l2_port_limit_read(const struct rtl_dq_io *io,
					unsigned int port, unsigned int *word)
{
	return rtl_l2_port_limit_access(io, port, word, 0);
}

static inline int rtl_l2_port_limit_write(const struct rtl_dq_io *io,
					 unsigned int port, unsigned int word)
{
	return rtl_l2_port_limit_access(io, port, &word, 1);
}

static inline int rtl_l2_table_read(const struct rtl_dq_io *io,
				    enum rtl_l2_table table, unsigned int index,
				    unsigned int *words)
{
	struct rtl_l2_table_layout layout;
	unsigned int copy[RTL_L2_TABLE_MAX_WORDS], i;
	int ret;

	if (!rtl_l2_io_valid(io) || !words || rtl_l2_table_layout(table, &layout) ||
	    index >= layout.entries)
		return -EINVAL;
	if (io->read(io->context, layout.access) & RTL_L2_ACCESS_BUSY)
		return -EBUSY;
	ret = io->indirect(io->context, layout.access, RTL_L2_ACCESS_BUSY | index);
	if (ret)
		return ret;
	for (i = 0; i < layout.words; i++)
		copy[i] = io->read(io->context, layout.data0 - i * 4);
	for (i = 0; i < layout.words; i++)
		words[i] = copy[i];
	return 0;
}

static inline int rtl_l2_table_write(const struct rtl_dq_io *io,
				     enum rtl_l2_table table, unsigned int index,
				     const unsigned int *words)
{
	struct rtl_l2_table_layout layout;
	unsigned int i;

	if (!rtl_l2_io_valid(io) || !words || rtl_l2_table_layout(table, &layout) ||
	    index >= layout.entries)
		return -EINVAL;
	if (io->read(io->context, layout.access) & RTL_L2_ACCESS_BUSY)
		return -EBUSY;
	for (i = 0; i < layout.words; i++)
		io->write(io->context, layout.data0 - i * 4, words[i]);
	return io->indirect(io->context, layout.access,
		RTL_L2_ACCESS_BUSY | RTL_L2_ACCESS_WRITE | index);
}

struct rtl_l2_snapshot {
	enum rtl_l2_table table;
	unsigned int index, words[RTL_L2_TABLE_MAX_WORDS];
	unsigned char valid;
};

static inline int rtl_l2_snapshot_take(const struct rtl_dq_io *io,
				       struct rtl_l2_snapshot *snapshot,
				       enum rtl_l2_table table, unsigned int index)
{
	struct rtl_l2_snapshot next = { .table = table, .index = index };
	int ret;

	if (!snapshot)
		return -EINVAL;
	/* Never overwrite the original snapshot of an already owned resource. */
	if (snapshot->valid)
		return -EALREADY;
	ret = rtl_l2_table_read(io, table, index, next.words);
	if (ret)
		return ret;
	next.valid = 1;
	*snapshot = next;
	return 0;
}

static inline int rtl_l2_snapshot_restore(const struct rtl_dq_io *io,
					  const struct rtl_l2_snapshot *snapshot)
{
	if (!snapshot || !snapshot->valid)
		return -EINVAL;
	/* Caller clears valid only after the entire dependent transaction has
 	 * quiesced and every restore completed. Errors must remain retryable. */
	return rtl_l2_table_write(io, snapshot->table, snapshot->index, snapshot->words);
}

struct rtl_l2_fdb_result {
	unsigned int raw, status, index, words[RTL_L2_FDB_WORDS];
};

static inline int rtl_l2_fdb_command(const struct rtl_dq_io *io,
				     enum rtl_l2_fdb_command command,
				     unsigned int start, const unsigned int *words,
				     struct rtl_l2_fdb_result *result)
{
	struct rtl_l2_fdb_result next = { 0 };
	unsigned int request = RTL_L2_ACCESS_BUSY | command, i;
	int ret;

	if (!rtl_l2_io_valid(io) || !result)
		return -EINVAL;
	switch (command) {
	case RTL_L2_FDB_SCAN:
		if (start >= RTL_L2_FDB_ENTRIES)
			return -EINVAL;
		request |= start << 8;
		break;
	case RTL_L2_FDB_READ:
	case RTL_L2_FDB_APPEND:
	case RTL_L2_FDB_DELETE:
		if (!words || start)
			return -EINVAL;
		break;
	default:
		return -EOPNOTSUPP;
	}
	if ((io->read(io->context, RTL_L2_FDB_ACCESS) |
	     io->read(io->context, RTL_L2_FDB_LIMIT_ACCESS)) & RTL_L2_ACCESS_BUSY)
		return -EBUSY;
	/* Mode is owned for the entire L2/FE lifetime. Changing it back while a
 	 * timed-out FDB/limit command is busy would change that transaction.
	 * Scans may run with hardware learning enabled; only mode changes need
	 * the stronger rtl_l2_fdb_mode_idle() learning-stop condition. */
	if (!(io->read(io->context, RTL_L2_FDB_CONTROL) & RTL_L2_FDB_CMD_MODE))
		return -EOPNOTSUPP;
	io->write(io->context, RTL_L2_FDB_RETURN, 0);
	for (i = 0; i < RTL_L2_FDB_WORDS; i++)
		io->write(io->context, RTL_L2_FDB_DATA0 - i * 4,
			command == RTL_L2_FDB_SCAN ? 0 : words[i]);
	ret = io->indirect(io->context, RTL_L2_FDB_ACCESS, request);
	if (ret)
		return ret;
	next.raw = io->read(io->context, RTL_L2_FDB_RETURN);
	next.status = next.raw & 15U;
	next.index = (next.raw >> 4) & 8191U;
	if ((command == RTL_L2_FDB_READ || command == RTL_L2_FDB_SCAN) &&
	    next.status == RTL_L2_FDB_STATUS_HIT)
		for (i = 0; i < RTL_L2_FDB_WORDS; i++)
			next.words[i] = io->read(io->context, RTL_L2_FDB_DATA0 - i * 4);
	/* 4 and 11 are not simply failure/no-write: the SDK reports mutation
 	 * despite a MAC limit failure. The owner must reconcile/undo by key.
 	 * Keep raw status visible rather than incorrectly claiming rollback. */
	*result = next;
	return 0;
}

/* One bounded hardware SCAN. 1 = one row, 0 = end, negative = fault. Start
 * the next call at result->index + 1. Do not delete absent software entries
 * until a COMPLETE successful scan; failed/partial scans prove no absence.
 * Learning can mutate rows between calls: this is reconciliation, not an
 * atomic whole-table snapshot. Skip static, multicast and foreign domains
 * in the owner, never modify them to make the walker convenient.
 */
static inline int rtl_l2_fdb_scan(const struct rtl_dq_io *io, unsigned int start,
				  struct rtl_l2_fdb_result *result)
{
	struct rtl_l2_fdb_result next;
	int ret;

	if (!result || start > RTL_L2_FDB_ENTRIES)
		return -EINVAL;
	if (start == RTL_L2_FDB_ENTRIES)
		return 0;
	ret = rtl_l2_fdb_command(io, RTL_L2_FDB_SCAN, start, 0, &next);
	if (ret)
		return ret;
	if (next.status == RTL_L2_FDB_STATUS_MISS)
		return 0;
	if (next.status != RTL_L2_FDB_STATUS_HIT || next.index < start ||
	    next.index >= RTL_L2_FDB_ENTRIES)
		return -EIO;
	*result = next;
	return 1;
}

#endif
