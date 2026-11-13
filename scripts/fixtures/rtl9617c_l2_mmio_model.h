/* SPDX-License-Identifier: GPL-2.0-only */
/* Deterministic MMIO transport for executing the production L2 helpers.
 * This models ordering/failure, not undocumented silicon or throughput.
 * Address/field accuracy has a separate externally pinned SDK oracle.
 */
#ifndef RTL9617C_L2_MMIO_MODEL_H
#define RTL9617C_L2_MMIO_MODEL_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "rtl9617c-l2-table.h"

enum l2_model_event_kind { L2_MODEL_READ, L2_MODEL_WRITE, L2_MODEL_COMMAND };
struct l2_model_event {
	enum l2_model_event_kind kind;
	unsigned int address, value;
};

struct l2_mmio_model {
	unsigned int registers[0x10000 / 4];
	unsigned int rows[RTL_L2_TBL_COUNT][RTL_L2_VLAN_IDS][RTL_L2_TABLE_MAX_WORDS];
	struct rtl_l2_table_layout layouts[RTL_L2_TBL_COUNT];
	bool checked_idle[RTL_L2_TBL_COUNT + 2];
	unsigned int port_limits[RTL_L2_LOGICAL_PORTS];
	struct l2_model_event events[128];
	unsigned int event_count, reads, writes, commands;
	bool pending;
	unsigned int pending_address, pending_value;
	unsigned int pending_words[RTL_L2_TABLE_MAX_WORDS];
	int next_error;
	unsigned int fdb_status, fdb_index, fdb_reply[RTL_L2_FDB_WORDS];
	unsigned int fdb_effects;
	bool complete_busy_fdb, complete_enable_learning;
};

static void l2_model_trace_reset(struct l2_mmio_model *model)
{
	model->event_count = model->reads = model->writes = model->commands = 0;
	memset(model->checked_idle, 0, sizeof(model->checked_idle));
}

static void l2_model_init(struct l2_mmio_model *model)
{
	unsigned int table;

	memset(model, 0, sizeof(*model));
	for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
		assert(!rtl_l2_table_layout(table, &model->layouts[table]));
		assert(model->layouts[table].words <= RTL_L2_TABLE_MAX_WORDS);
		assert(model->layouts[table].entries <= RTL_L2_VLAN_IDS);
	}
	model->registers[RTL_L2_FDB_CONTROL / 4] = RTL_L2_FDB_CMD_MODE | 0x01234567;
	model->fdb_status = RTL_L2_FDB_STATUS_HIT;
	model->fdb_index = 7;
}

static void l2_model_event(struct l2_mmio_model *model,
			   enum l2_model_event_kind kind,
			   unsigned int address, unsigned int value)
{
	assert(!(address & 3) && address < sizeof(model->registers));
	assert(model->event_count < sizeof(model->events) / sizeof(model->events[0]));
	model->events[model->event_count++] =
		(struct l2_model_event) { kind, address, value };
}

static unsigned int l2_model_read(void *context, unsigned int address)
{
	struct l2_mmio_model *model = context;
	unsigned int table, value;

	assert(!(address & 3) && address < sizeof(model->registers));
	value = model->registers[address / 4];
	for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
		const struct rtl_l2_table_layout *layout = &model->layouts[table];

		if (address == layout->access)
			model->checked_idle[table] = !(value & RTL_L2_ACCESS_BUSY);
		if (address <= layout->data0 &&
		    address > layout->data0 - layout->words * 4)
			assert(!(model->registers[layout->access / 4] & RTL_L2_ACCESS_BUSY));
	}
	if (address == RTL_L2_FDB_ACCESS)
		model->checked_idle[RTL_L2_TBL_COUNT] = !(value & RTL_L2_ACCESS_BUSY);
	if (address == RTL_L2_FDB_LIMIT_ACCESS)
		model->checked_idle[RTL_L2_TBL_COUNT + 1] = !(value & RTL_L2_ACCESS_BUSY);
	if (address == RTL_L2_FDB_LIMIT_DATA)
		assert(!(model->registers[RTL_L2_FDB_LIMIT_ACCESS / 4] & RTL_L2_ACCESS_BUSY));
	if ((address <= RTL_L2_FDB_DATA0 && address > RTL_L2_FDB_DATA0 - 16) ||
	    address == RTL_L2_FDB_RETURN)
		assert(!(model->registers[RTL_L2_FDB_ACCESS / 4] & RTL_L2_ACCESS_BUSY));
	l2_model_event(model, L2_MODEL_READ, address, value);
	model->reads++;
	return value;
}

static void l2_model_write(void *context, unsigned int address, unsigned int value)
{
	struct l2_mmio_model *model = context;
	unsigned int table;
	bool staging = false;

	for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
		const struct rtl_l2_table_layout *layout = &model->layouts[table];

		if (address <= layout->data0 && address > layout->data0 - layout->words * 4) {
			assert(model->checked_idle[table]);
			assert(!(model->registers[layout->access / 4] & RTL_L2_ACCESS_BUSY));
			staging = true;
		}
	}
	if ((address <= RTL_L2_FDB_DATA0 && address > RTL_L2_FDB_DATA0 - 16) ||
	    address == RTL_L2_FDB_RETURN) {
		assert(model->checked_idle[RTL_L2_TBL_COUNT]);
		assert(!(model->registers[RTL_L2_FDB_ACCESS / 4] & RTL_L2_ACCESS_BUSY));
		staging = true;
	}
	if (address == RTL_L2_FDB_LIMIT_DATA || address == RTL_L2_FDB_CONTROL) {
		assert(model->checked_idle[RTL_L2_TBL_COUNT]);
		assert(model->checked_idle[RTL_L2_TBL_COUNT + 1]);
		assert(!(model->registers[RTL_L2_FDB_ACCESS / 4] & RTL_L2_ACCESS_BUSY));
		assert(!(model->registers[RTL_L2_FDB_LIMIT_ACCESS / 4] & RTL_L2_ACCESS_BUSY));
		assert(model->registers[RTL_L2_FDB_CONTROL / 4] & RTL_L2_FDB_LEARN_DISABLE);
		if (address == RTL_L2_FDB_CONTROL)
			assert(!((value ^ model->registers[address / 4]) & ~RTL_L2_FDB_CMD_MODE));
		else
			assert(!(model->registers[RTL_L2_FDB_CONTROL / 4] & RTL_L2_FDB_CMD_MODE));
		staging = true;
	}
	/* The only non-DATA write is a checked exclusive MAC-limit mode lease. */
	assert(staging);
	l2_model_event(model, L2_MODEL_WRITE, address, value);
	model->writes++;
	model->registers[address / 4] = value;
}

static void l2_model_complete(struct l2_mmio_model *model)
{
	unsigned int table, word, address = model->pending_address;
	unsigned int value = model->pending_value;

	assert(model->pending && (model->registers[address / 4] & RTL_L2_ACCESS_BUSY));
	for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
		const struct rtl_l2_table_layout *layout = &model->layouts[table];
		unsigned int index = value & ~(RTL_L2_ACCESS_BUSY | RTL_L2_ACCESS_WRITE);

		if (address != layout->access)
			continue;
		assert(index < layout->entries);
		for (word = 0; word < layout->words; word++) {
			if (value & RTL_L2_ACCESS_WRITE) {
				assert(model->registers[(layout->data0 - word * 4) / 4] ==
				       model->pending_words[word]);
				model->rows[table][index][word] = model->pending_words[word];
			} else {
				model->registers[(layout->data0 - word * 4) / 4] =
					model->rows[table][index][word];
			}
		}
		break;
	}
	if (address == RTL_L2_FDB_ACCESS) {
		unsigned int command = value & 255;

		for (word = 0; word < RTL_L2_FDB_WORDS; word++)
			assert(model->registers[(RTL_L2_FDB_DATA0 - word * 4) / 4] ==
			       model->pending_words[word]);
		assert(model->registers[RTL_L2_FDB_CONTROL / 4] & RTL_L2_FDB_CMD_MODE);
		model->registers[RTL_L2_FDB_RETURN / 4] = model->fdb_index * 16 + model->fdb_status;
		if ((command == RTL_L2_FDB_READ || command == RTL_L2_FDB_SCAN) &&
		    model->fdb_status == RTL_L2_FDB_STATUS_HIT)
			for (word = 0; word < RTL_L2_FDB_WORDS; word++)
				model->registers[(RTL_L2_FDB_DATA0 - word * 4) / 4] = model->fdb_reply[word];
		if (command == RTL_L2_FDB_APPEND || command == RTL_L2_FDB_DELETE)
			model->fdb_effects++;
	} else if (address == RTL_L2_FDB_LIMIT_ACCESS) {
		unsigned int port = value & (RTL_L2_FDB_LIMIT_SELECT - 1);
		assert(port < RTL_L2_LOGICAL_PORTS && (value & RTL_L2_FDB_LIMIT_SELECT));
		assert(!(value & ~(RTL_L2_ACCESS_BUSY | RTL_L2_ACCESS_WRITE |
			RTL_L2_FDB_LIMIT_SELECT | (RTL_L2_LOGICAL_PORTS - 1))));
		assert(!(model->registers[RTL_L2_FDB_CONTROL / 4] & RTL_L2_FDB_CMD_MODE));
		assert(model->registers[RTL_L2_FDB_CONTROL / 4] & RTL_L2_FDB_LEARN_DISABLE);
		if (value & RTL_L2_ACCESS_WRITE) {
			assert(model->registers[RTL_L2_FDB_LIMIT_DATA / 4] == model->pending_words[0]);
			model->port_limits[port] = model->pending_words[0];
		} else {
			model->registers[RTL_L2_FDB_LIMIT_DATA / 4] = model->port_limits[port];
		}
		if (model->complete_busy_fdb)
			model->registers[RTL_L2_FDB_ACCESS / 4] |= RTL_L2_ACCESS_BUSY;
		if (model->complete_enable_learning)
			model->registers[RTL_L2_FDB_CONTROL / 4] &= ~RTL_L2_FDB_LEARN_DISABLE;
	} else {
		assert(table < RTL_L2_TBL_COUNT);
	}
	model->registers[address / 4] = 0;
	model->pending = false;
}

static int l2_model_command(void *context, unsigned int address, unsigned int value)
{
	struct l2_mmio_model *model = context;
	unsigned int table, word;
	int error = model->next_error;

	assert(!model->pending && !(model->registers[address / 4] & RTL_L2_ACCESS_BUSY));
	assert(value & RTL_L2_ACCESS_BUSY);
	for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
		const struct rtl_l2_table_layout *layout = &model->layouts[table];

		if (address == layout->access) {
			assert(model->checked_idle[table]);
			for (word = 0; word < layout->words; word++)
				model->pending_words[word] = model->registers[(layout->data0 - word * 4) / 4];
			break;
		}
	}
	if (address == RTL_L2_FDB_ACCESS) {
		assert(model->checked_idle[RTL_L2_TBL_COUNT]);
		for (word = 0; word < RTL_L2_FDB_WORDS; word++)
			model->pending_words[word] = model->registers[(RTL_L2_FDB_DATA0 - word * 4) / 4];
	} else if (address == RTL_L2_FDB_LIMIT_ACCESS) {
		assert(model->checked_idle[RTL_L2_TBL_COUNT]);
		assert(model->checked_idle[RTL_L2_TBL_COUNT + 1]);
		assert(!(model->registers[RTL_L2_FDB_CONTROL / 4] & RTL_L2_FDB_CMD_MODE));
		model->pending_words[0] = model->registers[RTL_L2_FDB_LIMIT_DATA / 4];
	} else {
		assert(table < RTL_L2_TBL_COUNT);
	}
	l2_model_event(model, L2_MODEL_COMMAND, address, value);
	model->commands++;
	model->pending = true;
	model->pending_address = address;
	model->pending_value = value;
	model->registers[address / 4] = value;
	model->next_error = 0;
	if (!error)
		l2_model_complete(model);
	return error;
}

static struct rtl_dq_io l2_model_io(struct l2_mmio_model *model)
{
	return (struct rtl_dq_io) { model, l2_model_read, l2_model_write, l2_model_command };
}

#endif
