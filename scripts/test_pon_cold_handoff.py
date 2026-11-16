#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the production NI-owned PON cold fence with reset-aware MMIO faults.

The model rejects every access to a held-reset or unselected MAC and to a
held-reset PDC FIFO. Optional generated-register and GPL source pins check
the actual vendor field layouts and reset polarity; this is not a hardware
clock, bus-response, optical, or DDR-retirement proof. Delayed gate visibility
models a completed MMIO request whose device-side admission acknowledgement
has not settled yet, not a host posted write that readl() should flush. It is
a software robustness oracle, not evidence that this is the board's cause.

--sdk-directory accepts a pinned ca-network-drivers checkout root or its
ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c directory.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
HEADER = DRIVER / 'rtl9617c-pon-cold.h'
SDK_SHA = 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0'
SDK_COMMIT = '8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0'
SDK_FILES = {
    'aal_pon.c': '88339786b332d551122ee87756859f7132f6373fb3d36cf4114bfff4aa9bf92f',
    'aal_gpon.c': '2abec1bb5fd63fc3c6ee1a5f4d6f696db445aff5a55743392f820d72376c87fc',
    'aal_psds.c': '726aff7f14946c4d038632fa62489e83cd8c2d32bf375a9ba00242d959751245',
    'aal_epon_mac.c': '81cccb42f500ba1324ad47202bcfa99920b07987780caea6d1c34ac01fe30b74',
    'aal_xgpon.c': '2b1e286531c3a99ff37cc9c858df96dbcefd6c460431ed4853369c51773ad589',
}


def function(source, name):
    match = re.search(r'\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', source)
    if not match:
        raise ValueError('Missing source function ' + name)
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return re.sub(r'\s+', '', source[match.start():end])


def sdk_sources(directory):
    if directory is None:
        return
    if not (directory / 'aal_pon.c').is_file():
        directory /= 'ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c'
    texts = {}
    for name, digest in SDK_FILES.items():
        raw = (directory / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SystemExit(f'{name}: GPL SDK pin mismatch ({SDK_COMMIT})')
        texts[name] = raw.decode()
    contracts = (
        ('aal_pon.c', 'aal_pon_mac_enable_set', (
            'if(CA_PON_MODE_IS_EPON_FAMILY(aal_pon_mac_mode))',
            'mac_ctrl.mac_en=0;', 'aal_gpon_active_set(device_id,rx_en)',
        )),
        ('aal_gpon.c', 'aal_gpon_active_set', (
            'onu_ctl.bf.en=active;', 'AAL_PON_REG_WRITE(onu_ctl.wrd,GPON_MAC_GPON_onu_ctl)',
        )),
        ('aal_epon_mac.c', 'aal_epon_mac_sw_reset_set', (
            'glb_pon_cntl.bf.pdc_reset=0;', 'glb_pon_cntl.bf.pdc_reset=1;',
        )),
        ('aal_epon_mac.c', 'aal_epon_csr_reset', (
            'cntl.bf.epon_rst_n=0;', 'cntl.bf.onugepn_rst_n=0;',
            'cntl.bf.xgepn_rst_n=0;', 'cntl.bf.epon_rst_n=1;',
            'cntl.bf.onugepn_rst_n=1;', 'cntl.bf.xgepn_rst_n=1;',
        )),
        ('aal_xgpon.c', '__glb_gpon_ctrl_init', (
            'AAL_GLB_REG_WRITE(0x00E,GLOBAL_PON_CNTL)',
            'AAL_GLB_REG_WRITE(0x30E,GLOBAL_PON_CNTL)',
            'AAL_GLB_REG_WRITE(0x003,GLOBAL_GPON_CNTL)',
            'AAL_GLB_REG_WRITE(0x205,GLOBAL_GPON_CNTL)',
            'AAL_GLB_REG_WRITE(0x305,GLOBAL_GPON_CNTL)',
        )),
        ('aal_xgpon.c', 'aal_xgpon_xgpn_glb_ctrl_set', (
            'xgpn_glb_ctrl.wrd=AAL_PON_REG_READ(XGPN_XGPN_GLB_CTRL)',
            'xgpn_glb_ctrl.bf.mac_en=glb_ctrl_cfg->mac_en;',
            'AAL_PON_REG_WRITE(xgpn_glb_ctrl.wrd,XGPN_XGPN_GLB_CTRL)',
        )),
        ('aal_xgpon.c', 'aal_xgpon_tcont_flush', (
            'xgpn_glb_ctrl.flush_en=1;', 'if(!xgpn_glb_ctrl.flush_en)',
        )),
        ('aal_xgpon.c', 'aal_xgpon_clk_is_locked_ok', ('returnTRUE;',)),
        ('aal_psds.c', '__psds_eth_csr_reset', (
            'AAL_GLB_REG_WRITE(0x30000,GLOBAL_EPON_CNTL)',
            'AAL_GLB_REG_WRITE(0x30200,GLOBAL_EPON_CNTL)',
        )),
        ('aal_psds.c', 'aal_psds_out_of_reset', (
            'AAL_GLB_REG_FIELD_WRITE(GLOBAL_EPON_CNTL,epon_rst_n,0)',
        )),
        ('aal_psds.c', 'aal_psds_init', (
            'AAL_GLB_REG_FIELD_WRITE(GLOBAL_PON_CNTL,epon_mode,0x1)',
            'AAL_GLB_REG_FIELD_WRITE(GLOBAL_PON_CNTL,epon_mode,0x0)',
        )),
        ('aal_psds.c', '__psds_sync', (
            '.bf.CKRDY_RX=1,', '.bf.CKRDY_TX=1,', '.bf.CKRDY_MPCP=1,',
            'status=AAL_PON_REG_READ(PSDS_RGB8)',
        )),
    )
    for name, symbol, snippets in contracts:
        body = function(texts[name], symbol)
        for snippet in snippets:
            assert snippet in body, (name, symbol, snippet)
    print('PASS: five pinned GPL SDK files; family mux, reset polarity, held-reset EPON and Active Ethernet contracts')


def sdk_oracle(path):
    if path is None:
        return 'static void sdk_oracle(void) {}\n'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SDK_SHA:
        raise SystemExit('RTL8277C generated header pin mismatch')
    source = raw.decode()
    gates = {
        'EPON_1G': ('EPON_ONU_EPON_RXCTRL', 'RX_EN'),
        'EPON_10G': ('EPON_XGEPN_XMAC_RXMAC_RX_CONFIG', 'mac_en'),
        'GPON': ('GPON_MAC_GPON_onu_ctl', 'en'),
        'XGPON': ('XGPN_XGPN_GLB_CTRL', 'mac_en'),
    }
    globals_ = {
        'GLOBAL_PON_CNTL': (
            ('epon_mode', 'RTL_PON_COLD_EPON_MODE'),
            ('pdc_reset', 'RTL_PON_COLD_PDC_RELEASED'),
            ('psds_reg_rst_n', 'RTL_PON_COLD_PSDS_CSR_RELEASED'),
        ),
        'GLOBAL_EPON_CNTL': (
            ('epon_rst_n', 'RTL_PON_COLD_EPON_RELEASED'),
            ('onugepn_rst_n', 'RTL_PON_COLD_EPON_1G_RELEASED'),
            ('xgepn_rst_n', 'RTL_PON_COLD_EPON_10G_RELEASED'),
            ('act_eth_rst_n', 'RTL_PON_COLD_ACTIVE_ETH_RELEASED'),
            ('epon_ethernet_mode', 'RTL_PON_COLD_EPON_ETHERNET_MODE'),
        ),
        'GLOBAL_GPON_CNTL': (
            ('ani_rst_n', 'RTL_PON_COLD_ANI_RELEASED'),
            ('gpon_rst_n', 'RTL_PON_COLD_GPON_RELEASED'),
            ('xgpn_rst_n', 'RTL_PON_COLD_XGPON_RELEASED'),
        ),
    }
    output = ''
    for name in [*(r[0] for r in gates.values()), *globals_, 'PDC_FIFO_STATUS',
                 'PSDS_MODE', 'PSDS_RGB8', 'PSDS_GBOX_CTRL', 'PDC_CTRL']:
        start = re.search(r'^#define ' + name + r'\s+0x', source, re.M).start()
        end = source.index('#endif /* !__ASSEMBLER__ */', start)
        output += source[start:end] + '#endif\n'
    output += 'static void sdk_oracle(void) {\n'
    for name, (register, field) in gates.items():
        output += f'{{ {register}_t word={{.wrd=~0U}}; word.bf.{field}=0;\n'
        output += f'assert(rtl_pon_cold_gates[RTL_PON_COLD_GATE_{name}].reg=={register}-0xf5500000U);\n'
        output += f'assert(word.wrd==~rtl_pon_cold_gates[RTL_PON_COLD_GATE_{name}].mask); }}\n'
    for register, fields in globals_.items():
        for field, mask in fields:
            assertion = f'{{ {register}_t word={{.wrd=0}}; word.bf.{field}=1; assert(word.wrd=={mask}); }}\n'
            # Keep the optional historical-header run usable without
            # weakening its original, required reset/mux field checks.
            output += (f'#ifdef {mask}\n{assertion}#endif\n'
                       if mask == 'RTL_PON_COLD_PSDS_CSR_RELEASED' else assertion)
    output += '''
 assert(RTL_PON_COLD_CONTROL==GLOBAL_PON_CNTL);
 assert(RTL_PON_COLD_EPON_CONTROL==GLOBAL_EPON_CNTL);
 assert(RTL_PON_COLD_GPON_CONTROL==GLOBAL_GPON_CNTL);
 PDC_FIFO_STATUS_t fifo={.wrd=~0U}; fifo.bf.depth=0;
 assert(RTL_PON_COLD_PDC_FIFO_STATUS==PDC_FIFO_STATUS-0xf5500000U);
 assert(fifo.wrd==~RTL_PON_COLD_PDC_FIFO_DEPTH);
#ifdef RTL_PON_COLD_XGPON_COMMANDS
 XGPN_XGPN_GLB_CTRL_t command={.wrd=0};
 command.bf.flush_en=1;command.bf.sw_reset_pmac=1;
 assert(command.wrd==RTL_PON_COLD_XGPON_COMMANDS);
 assert(RTL_PON_COLD_PSDS_MODE==PSDS_MODE-0xf5500000U);
 assert(RTL_PON_COLD_PSDS_STATUS==PSDS_RGB8-0xf5500000U);
 assert(RTL_PON_COLD_PSDS_GBOX==PSDS_GBOX_CTRL-0xf5500000U);
 assert(RTL_PON_COLD_PDC_CONTROL==PDC_CTRL-0xf5500000U);
 PSDS_RGB8_t clocks={.wrd=0};
 clocks.bf.CKRDY_RX=1;clocks.bf.CKRDY_TX=1;clocks.bf.CKRDY_MPCP=1;
 assert(clocks.wrd==RTL_PON_COLD_PSDS_CLOCKS_READY);
#endif
}
'''
    return output


SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t ca_uint32_t;
static unsigned waits;
static void device_settle(void);
static void usleep_range(unsigned low,unsigned high) {
 assert(low==100 && high==200);waits++;device_settle();
}
#include "rtl9617c-pon-cold.h"
static unsigned regs[0xc000/4],saved[0xc000/4],global[3],initial[3],global_reads[3];
static const unsigned offsets[]={0x088c,0x10b4,0x6114,0x4004};
static const unsigned masks[]={1U,1U<<7,1U<<1,3U};
static const unsigned global_regs[]={0xf4320094U,0xf4320074U,0xf432007cU};
static unsigned allowed,mac_reads,writes,fifo_reads,busy_left,stuck_index,stuck_mask;
static unsigned drift_index,drift_on_read,drift_mask,drift_on_wait;
static unsigned drift_mac_index,drift_mac_read,drift_fifo_read;
static unsigned gate_reads[4],gate_writes[4],gate_delay[4],gate_due[4],gate_requested[4];
static unsigned gate_pending,gate_waits,ones_index,ones_on_read,fifo_ones_on_read;
static unsigned psds_reads,psds_allones_on_read,psds_clock_drop_on_read;
static unsigned flicker_index,change_index,change_wait,change_mask;
static int observed_snapshot_drift;
static int expected_error,fifo_stuck,fifo_flicker,verify_busy;
static void device_settle(void) {
 if(drift_index<3 && waits==drift_on_wait)global[drift_index]^=drift_mask;
 if(fifo_reads)return;
 gate_waits++;
 for(unsigned i=0;i<4;i++)if((gate_pending&(1U<<i)) && gate_waits>=gate_due[i]) {
  /* The non-gate register fields were written synchronously. Only the
   * device's gate acknowledgement changes after the configured interval. */
  regs[offsets[i]/4]=(regs[offsets[i]/4]&~masks[i])|(gate_requested[i]&masks[i]);
  gate_pending&=~(1U<<i);
 }
 if(flicker_index<4) {
  if(gate_waits==1)regs[offsets[flicker_index]/4]|=masks[flicker_index];
  if(gate_waits==2)regs[offsets[flicker_index]/4]&=~masks[flicker_index];
 }
 if(change_index<4 && gate_waits==change_wait)regs[offsets[change_index]/4]^=change_mask;
}
static unsigned read_reg(void *ctx,unsigned reg) {
 (void)ctx;
 for(unsigned i=0;i<3;i++)if(reg==global_regs[i]) {
  global_reads[i]++;
  if(drift_index==i && global_reads[i]==drift_on_read)global[i]^=drift_mask;
  if(global[i]!=initial[i])observed_snapshot_drift=1;
  return global[i];
 }
 if(reg==RTL_PON_COLD_PSDS_STATUS) {
  assert((initial[0]&0x204)==0x204 && (allowed&(1U<<RTL_PON_COLD_GATE_XGPON)));
  psds_reads++;
  if(psds_clock_drop_on_read && psds_reads==psds_clock_drop_on_read)
   regs[RTL_PON_COLD_PSDS_STATUS/4]&=~RTL_PON_COLD_PSDS_CLOCKS_READY;
  if(psds_allones_on_read && psds_reads==psds_allones_on_read)return ~0U;
  return regs[RTL_PON_COLD_PSDS_STATUS/4];
 }
 /* Reject access to every held-reset PDC or unsupported/ambiguous mode. */
 assert((initial[0]&0x200) && !expected_error && !observed_snapshot_drift);
 assert(!memcmp(global,initial,sizeof(global)));
 if(reg==0x9010) {
  for(unsigned i=0;i<4;i++)if(allowed&(1U<<i))assert(!(regs[offsets[i]/4]&masks[i]));
  fifo_reads++;
  if(fifo_reads==drift_fifo_read)global[drift_index]^=drift_mask;
  if(fifo_reads==fifo_ones_on_read)return ~0U;
  if(fifo_stuck || (verify_busy && fifo_reads>=4))return 0xc001;
  if(busy_left){busy_left--;return 0xc001;}
  if(fifo_flicker && fifo_reads==3)return 0xc001;
  return 0xc000;
 }
 for(unsigned i=0;i<4;i++)if(reg==offsets[i]) {
  /* This is an access fault, not a benign zero-filled inactive register. */
  assert(allowed&(1U<<i));mac_reads++;gate_reads[i]++;
  if(i==ones_index && gate_reads[i]==ones_on_read)return ~0U;
  if(i==drift_mac_index && gate_reads[i]==drift_mac_read)global[drift_index]^=drift_mask;
  return regs[reg/4];
 }
 assert(!"unexpected register read");return 0;
}
static void write_reg(void *ctx,unsigned reg,unsigned value) {
 (void)ctx;unsigned i;
 for(i=0;i<4;i++)if(reg==offsets[i])break;
 /* GLOBAL, TX, reset and unrelated registers must NEVER be written. */
 assert(i<4 && (allowed&(1U<<i)) && !observed_snapshot_drift);
 assert(!memcmp(global,initial,sizeof(global)));
 assert(regs[reg/4]!=~0U);
 assert((value&~masks[i])==(saved[reg/4]&~masks[i]));
 assert(!(value&masks[i]));
 assert(i!=3 || !(value&0xc0000000U)); /* Never reissue reset/flush. */
 writes++;gate_writes[i]++;gate_requested[i]=value;
 assert(gate_writes[i]==1); /* Settling is a read-only wait, never replay. */
 if(gate_delay[i]) { gate_pending|=1U<<i;gate_due[i]=gate_waits+gate_delay[i]; }
 else regs[reg/4]=value;
 if(i==stuck_index)regs[reg/4]|=stuck_mask;
}
static const struct rtl_dq_io io={.read=read_reg,.write=write_reg};
static void setup(unsigned control,unsigned epon,unsigned gpon,unsigned seed) {
 global[0]=control;global[1]=epon;global[2]=gpon;
 memcpy(initial,global,sizeof(global));memset(global_reads,0,sizeof(global_reads));
 for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i++)regs[i]=(i*2654435761U)^seed;
 for(unsigned i=0;i<4;i++)regs[offsets[i]/4]|=masks[i];
 regs[0x4004/4]&=~0xc0000000U; /* command-busy fixtures are separate. */
 if((control&0x204)==0x204 && !(control&1) && (gpon&4))
  regs[RTL_PON_COLD_PSDS_STATUS/4]=RTL_PON_COLD_PSDS_CLOCKS_READY;
 memcpy(saved,regs,sizeof(regs));
 writes=mac_reads=fifo_reads=busy_left=waits=0;allowed=0;expected_error=0;
 memset(gate_reads,0,sizeof(gate_reads));memset(gate_writes,0,sizeof(gate_writes));
 memset(gate_delay,0,sizeof(gate_delay));memset(gate_due,0,sizeof(gate_due));
 memset(gate_requested,0,sizeof(gate_requested));gate_pending=gate_waits=0;
 ones_index=flicker_index=change_index=4;ones_on_read=fifo_ones_on_read=0;
 change_wait=change_mask=0;observed_snapshot_drift=0;
 psds_reads=psds_allones_on_read=psds_clock_drop_on_read=0;
 fifo_stuck=fifo_flicker=verify_busy=0;stuck_index=4;stuck_mask=0;
 drift_index=3;drift_on_read=drift_on_wait=0;drift_mask=0;
 drift_mac_index=4;drift_mac_read=drift_fifo_read=0;
 if(!(control&0x200))return;
 /* Independent contract oracle: raw numeric SDK fields, not driver macros. */
 if(control&1) {
  if(epon&(0x200|0x40000)){expected_error=-EOPNOTSUPP;return;}
  if((epon&12) && !(epon&1)){expected_error=-EOPNOTSUPP;return;}
  if(epon&4)allowed|=1;
  if(epon&8)allowed|=2;
 }else{
  if((gpon&6) && !(gpon&1)){expected_error=-EOPNOTSUPP;return;}
  if(gpon&2)allowed|=4;
  if(gpon&4)allowed|=8;
 }
}
static void unchanged_except_gates(void) {
 for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i++) {
  unsigned clear=0;
  for(unsigned j=0;j<4;j++)if(i==offsets[j]/4 && (allowed&(1U<<j)))clear=masks[j];
  assert(regs[i]==(saved[i]&~clear));
 }
 assert(!memcmp(initial,global,sizeof(global)));
}
static void valid_case(struct rtl_pon_cold_state *state) {
 unsigned before=writes;
 assert(!rtl_pon_cold_quiesce(&io,state));
 assert(state->ready && state->stage==RTL_PON_COLD_READY && !state->error);
 assert(state->control==initial[0] && state->epon_control==initial[1] && state->gpon_control==initial[2]);
 assert(state->gated_mask==allowed);
 assert(state->gate_sampled_mask==allowed && state->gate_written_mask==allowed);
 assert(state->gate_polls==(allowed?RTL_PON_COLD_GATE_STABLE:0));
 assert(state->gate_stable==(allowed?RTL_PON_COLD_GATE_STABLE:0));
 assert(state->gate_closed_mask==allowed && !state->gate_reopened_mask);
 assert(state->gate_changed_mask==allowed);
 for(unsigned i=0;i<4;i++) {
  assert(state->gate_before[i]==((allowed&(1U<<i))?saved[offsets[i]/4]:0));
  assert(state->gate_requested[i]==((allowed&(1U<<i))?(saved[offsets[i]/4]&~masks[i]):0));
  assert(state->gate_readback[i]==state->gate_requested[i]);
  assert(gate_writes[i]==!!(allowed&(1U<<i)));
  assert(state->gate_changes[i]==!!(allowed&(1U<<i)));
  assert(state->gate_first_closed_poll[i]==!!(allowed&(1U<<i)));
 }
 assert(state->pdc_active==!!(initial[0]&0x200));
 if(allowed&(1U<<RTL_PON_COLD_GATE_XGPON)) {
  assert(state->clock_required==RTL_PON_COLD_PSDS_CLOCKS_READY);
  assert(state->clock_valid && state->clock_ready && state->clock_samples>2);
  assert(state->clock_first==RTL_PON_COLD_PSDS_CLOCKS_READY);
 } else assert(!state->clock_samples && !state->clock_required);
 assert(state->fifo_polls==fifo_reads);
 if(!state->pdc_active)assert(!mac_reads && !writes && !fifo_reads && !waits);
 unchanged_except_gates();
 unsigned after=writes;
 assert(!rtl_pon_cold_verify(&io,state));
 assert(state->ready && writes==after && after>=before);
 unchanged_except_gates();
}
'''

CASES = r'''
/* Independent observer bus: only raw configuration/status words. Gate,
 * FIFO, PM counters, interrupt and indirect-window reads abort. */
static const unsigned observe_regs[]={
 0xf4320094U,0xf4320074U,0xf432007cU,0xa02c,0xa060,0xa064,0x9014,
};
static unsigned observe_values[7],observe_reads[7],observe_original[3];
static unsigned observe_drift_on,observe_drift_target,observe_drift_bit,observe_ones;
static unsigned observe_read(void *ctx,unsigned reg) {
 (void)ctx;
 for(unsigned i=0;i<7;i++)if(reg==observe_regs[i]) {
  observe_reads[i]++;
  if(i>=3) {
   assert(observe_original[0]&0x200);
   assert(i==6 || (observe_original[0]&4));
   assert(!memcmp(observe_original,observe_values,sizeof(observe_original)));
  }
  unsigned value=i==observe_ones?~0U:observe_values[i];
  if(i==observe_drift_on)observe_values[observe_drift_target]^=1U<<observe_drift_bit;
  return value;
 }
 assert(!"unowned diagnostic register");return 0;
}
static const struct rtl_dq_io observe_io={.read=observe_read};
static void observe_setup(unsigned control) {
 const unsigned initial_values[]={0,0x30000,0x205,0x451,0x9c00,0x454,2};
 memcpy(observe_values,initial_values,sizeof(observe_values));observe_values[0]=control;
 memcpy(observe_original,observe_values,sizeof(observe_original));
 memset(observe_reads,0,sizeof(observe_reads));
 observe_drift_on=observe_ones=7;observe_drift_target=observe_drift_bit=0;
}
static unsigned snapshot_cases(void) {
 struct rtl_pon_cold_snapshot snapshot;
 unsigned cases=0;
 for(unsigned pdc=0;pdc<2;pdc++)for(unsigned csr=0;csr<2;csr++) {
  observe_setup((pdc<<9)|(csr<<2));
  unsigned expected=7U|(pdc?0x40U:0)|(pdc&&csr?0x38U:0);
  assert(!rtl_pon_cold_snapshot(&observe_io,&snapshot));
  assert(snapshot.stable && !snapshot.error);
  assert(snapshot.sampled_mask==expected && snapshot.valid_mask==expected);
  for(unsigned i=0;i<7;i++) {
   assert(!!observe_reads[i]==!!(expected&(1U<<i)));
   assert(snapshot.value[i]==((expected&(1U<<i))?observe_values[i]:0));
  }
  cases++;
 }
 /* Clock bits are raw observations. Neither absent sync nor LOS blocks a
  * snapshot or is promoted to an admission/DDR completion condition. */
 for(unsigned status=0;status<32;status++) {
  observe_setup(0x30e);observe_values[4]=(status<<10)|(status&1);
  assert(!rtl_pon_cold_snapshot(&observe_io,&snapshot));
  assert(snapshot.stable && snapshot.value[4]==observe_values[4]);cases++;
 }
 for(unsigned missing=0;missing<7;missing++) {
  observe_setup(0x30e);observe_ones=missing;
  assert(rtl_pon_cold_snapshot(&observe_io,&snapshot)==-EIO);
  assert(!snapshot.stable && snapshot.refused_register==observe_regs[missing]);
  assert(snapshot.refused_value==~0U && snapshot.value[missing]==~0U);
  assert(snapshot.sampled_mask==(1U<<(missing+1))-1);
  assert(snapshot.valid_mask==(1U<<missing)-1);
  for(unsigned i=missing+1;i<7;i++)assert(!observe_reads[i]);
  cases++;
 }
 /* Reset/mux changes during any selected-domain read, including the
  * final PDC control read, invalidate the bracketed observation. */
 for(unsigned domain=3;domain<7;domain++)for(unsigned target=0;target<3;target++)
 for(unsigned bit=0;bit<32;bit++) {
  observe_setup(0x30e);observe_drift_on=domain;observe_drift_target=target;observe_drift_bit=bit;
  assert(rtl_pon_cold_snapshot(&observe_io,&snapshot)==-EAGAIN);
  assert(!snapshot.stable && snapshot.refused_register==observe_regs[target]);
  assert(snapshot.refused_value==(observe_original[target]^(1U<<bit)));
  for(unsigned i=domain+1;i<7;i++)assert(!observe_reads[i]);
  cases++;
 }
 struct rtl_dq_io bad={0};
 assert(rtl_pon_cold_snapshot(NULL,&snapshot)==-EINVAL);
 assert(rtl_pon_cold_snapshot(&bad,&snapshot)==-EINVAL);
 assert(rtl_pon_cold_snapshot(&observe_io,NULL)==-EINVAL);
 return cases;
}
int main(void) {
 struct rtl_pon_cold_state state={0};unsigned cases=0;
 sdk_oracle();
 cases+=snapshot_cases();
 /* R12 hardware observation: the NI executes its cold attempt before PON
  * SerDes reports CKRDY RX/TX/MPCP. Never write mac_en in this state. */
 setup(0x30e,0x30000,0x205,0);
 regs[0x4004/4]=saved[0x4004/4]=0x61;
 regs[RTL_PON_COLD_PSDS_STATUS/4]=0x4000;
 assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
 assert(state.stage==RTL_PON_COLD_CLOCK && state.refused_register==RTL_PON_COLD_PSDS_STATUS);
 assert(state.clock_required==RTL_PON_COLD_PSDS_CLOCKS_READY && state.clock_first==0x4000);
 assert(state.clock_samples==1 && state.clock_valid && !state.clock_ready);
 assert(!writes && !mac_reads && !fifo_reads && !waits);cases++;
 /* An all-ones PSDS status is an unmapped/broken domain, not clocks-ready. */
 setup(0x30e,0x30000,0x205,0);psds_allones_on_read=1;
 assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
 assert(state.stage==RTL_PON_COLD_CLOCK && state.clock_samples==1 && !state.clock_valid);
 assert(!writes && !mac_reads && !fifo_reads);cases++;
 /* A ready first observation followed by a lost clock before gate write
  * is not permission to touch that MAC. */
 setup(0x30e,0x30000,0x205,0);psds_clock_drop_on_read=2;
 assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
 assert(state.clock_samples==2 && state.clock_valid && !state.clock_ready);
 assert(!writes && !fifo_reads);cases++;
 /* A clock-domain regression while waiting for MAC acknowledgement
  * terminates the transaction before accepting a fabricated closed gate. */
 setup(0x30e,0x30000,0x205,0);psds_clock_drop_on_read=3;
 assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
 assert(state.clock_samples==3 && writes==1 && !fifo_reads);
 assert(state.stage==RTL_PON_COLD_CLOCK);cases++;
 /* Post-quiesce, post-fabric revalidation must refuse a lost PSDS clock. */
 setup(0x30e,0x30000,0x205,0);
 assert(!rtl_pon_cold_quiesce(&io,&state));
 unsigned observed=psds_reads,before_writes=writes;
 regs[RTL_PON_COLD_PSDS_STATUS/4]&=~RTL_PON_COLD_PSDS_CLOCKS_READY;
 assert(rtl_pon_cold_verify(&io,&state)==-EAGAIN);
 assert(state.stage==RTL_PON_COLD_CLOCK && psds_reads==observed+1 && writes==before_writes);
 cases++;
 /* A loss at the first FIFO preflight must refuse before any FIFO read. */
 setup(0x30e,0x30000,0x205,0);psds_clock_drop_on_read=8;
 assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
 assert(state.stage==RTL_PON_COLD_CLOCK && state.clock_samples==8);
 assert(writes==1 && !fifo_reads);cases++;
 /* The verify-time FIFO guard is independently necessary even when the
  * earlier MAC gate read succeeded; don't accept an unready clock. */
 setup(0x30e,0x30000,0x205,0);assert(!rtl_pon_cold_quiesce(&io,&state));
 observed=psds_reads;unsigned before_fifo=fifo_reads;
 psds_clock_drop_on_read=observed+2;
 assert(rtl_pon_cold_verify(&io,&state)==-EAGAIN);
 assert(state.stage==RTL_PON_COLD_CLOCK && fifo_reads==before_fifo);
 cases++;
 /* R11 real failure values: a refused low-bit clear stays a failure, with
  * no FIFO/fabric access and no fabricated retry or command completion. */
 setup(0x30e,0x30000,0x205,0);
 regs[0x4004/4]=saved[0x4004/4]=0x61;stuck_index=3;stuck_mask=1;
 assert(rtl_pon_cold_quiesce(&io,&state)==-ETIMEDOUT);
 assert(state.gate_before[3]==0x61 && state.gate_requested[3]==0x60 && state.gate_readback[3]==0x61);
 assert(state.gate_polls==1000 && !state.gate_closed_mask && !state.gate_changed_mask);
 assert(!state.gate_reopened_mask && !state.gate_first_closed_poll[3] && !state.gate_changes[3]);
 assert(gate_writes[3]==1 && !fifo_reads);cases++;
 /* TCONT flush and PMAC reset occupy the same register as mac_en. A cold
  * RMW must not replay either command, including with mac_en already zero. */
 for(unsigned bits=1;bits<4;bits++)for(unsigned enabled=0;enabled<2;enabled++) {
  setup(0x30e,0x30000,0x205,0);
  regs[0x4004/4]=saved[0x4004/4]=0x60|enabled|(bits<<30);
  assert(rtl_pon_cold_quiesce(&io,&state)==-EBUSY);
  assert(state.stage==RTL_PON_COLD_GATE && !state.ready && !writes && !fifo_reads);
  assert(state.refused_register==0x4004 && state.refused_value==regs[0x4004/4]);cases++;
 }
 for(unsigned bit=30;bit<=31;bit++) {
  setup(0x30e,0x30000,0x205,0);
  change_index=3;change_wait=1;change_mask=1U<<bit;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EBUSY);
  assert(state.stage==RTL_PON_COLD_READBACK && !state.ready && writes==1 && !fifo_reads);cases++;
  setup(0x30e,0x30000,0x205,0);
  assert(!rtl_pon_cold_quiesce(&io,&state));
  regs[0x4004/4]|=1U<<bit;
  assert(rtl_pon_cold_verify(&io,&state)==-EBUSY);
  assert(state.stage==RTL_PON_COLD_VERIFY && !state.ready && writes==1 && fifo_reads==4);cases++;
 }
 /* Synthetic XG admission word with unrelated fields 0xa0. The
  * backend deliberately acknowledges the ONE completed request after two
  * sleep intervals. This is an admissible robustness case, not a claim
  * that the physical failure was caused by asynchronous acknowledgement. */
 setup(0x30e,0x30000,0x305,0);
 regs[0x4004/4]=saved[0x4004/4]=0xa2;gate_delay[3]=2;
 assert(!rtl_pon_cold_quiesce(&io,&state));
 assert(state.ready && state.gated_mask==8 && state.gate_written_mask==8);
 assert(state.gate_sampled_mask==8 && state.gate_before[3]==0xa2);
 assert(state.gate_requested[3]==0xa0 && state.gate_readback[3]==0xa0);
 assert(state.gate_polls==5 && state.gate_stable==3 && gate_waits==4);
 assert(gate_writes[3]==1 && writes==1 && fifo_reads==4);cases++;
 /* Every mux, PDC, parent/child reset, AE hint and ignored high-bit state.
  * Inactive-family register access aborts the process immediately. */
 for(unsigned mode=0;mode<2;mode++)for(unsigned pdc=0;pdc<2;pdc++)
 for(unsigned ep=0;ep<16;ep++)for(unsigned gp=0;gp<8;gp++)
 for(unsigned ae=0;ae<4;ae++)for(unsigned seed=0;seed<4;seed++) {
  setup(0x80000000U|(pdc<<9)|mode,
        0x40000000U|(seed<<16)|ep|((ae&1)<<9)|((ae&2)<<17),
        0x80000300U|gp,0x76543210U^(seed*0x11111111U));
  if(expected_error) {
   assert(rtl_pon_cold_quiesce(&io,&state)==expected_error);
   assert(!state.ready && state.stage==RTL_PON_COLD_SELECT);
   assert(!writes && !mac_reads && !fifo_reads && !waits);
   assert(!memcmp(regs,saved,sizeof(regs)));
  }else if(pdc && !mode && (gp&5)==5) {
   /* PSDS CSR is held in reset in these generated combinations. The
    * released XGPON MAC is therefore not authorized for a gate write. */
   assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
   assert(state.stage==RTL_PON_COLD_CLOCK && !state.clock_samples);
   assert(state.clock_required==RTL_PON_COLD_PSDS_CLOCKS_READY);
   assert(state.refused_register==RTL_PON_COLD_CONTROL);
   assert(!writes && !mac_reads && !fifo_reads);
  }else valid_case(&state);
  cases++;
 }
 /* Known SDK cold/active states: zero PDC, GPON, XG-PON, XGS-PON,
  * all-released ITU, EPON 1G, D10G and bidirectional 10G. */
 const unsigned recipes[][3]={
  {0,0x30000,0x300},{0x30e,0x300ee,3},{0x30e,0x300ee,0x205},
  {0x30e,0x300ee,0x305},{0x30e,0x300ee,0x307},
  {0x30f,0x100ef,0x300},{0x30f,0x200ef,0x300},{0x30f,0x300ef,0x300},
 };
 for(unsigned n=0;n<sizeof(recipes)/sizeof(recipes[0]);n++)for(unsigned bit=0;bit<32;bit++) {
  setup(recipes[n][0],recipes[n][1],recipes[n][2],1U<<bit);
  busy_left=n;valid_case(&state);
  if(initial[0]&0x200)assert(fifo_reads==n+5 && waits==n+2+(allowed?2:0));
  cases++;
 }
 /* All SDK gate families, including simultaneous released children. Vary
  * acknowledgement latency independently; every sweep must close ALL
  * selected gates and may not access the opposite held-reset family. */
 const unsigned delays[]={0,1,2,7,31,RTL_PON_COLD_GATE_POLLS-RTL_PON_COLD_GATE_STABLE};
 for(unsigned target=0;target<4;target++)
 for(unsigned both=0;both<2;both++)
 for(unsigned delay=0;delay<sizeof(delays)/sizeof(delays[0]);delay++) {
  unsigned ep=target<2?(both?0xf:(1U|(4U<<target))):0;
  unsigned gp=target>=2?(both?7:(1U|(2U<<(target-2)))):0;
  setup(target<2?0x30f:0x30e,ep,gp,0x19283746);
  gate_delay[target]=delays[delay];
  assert(!rtl_pon_cold_quiesce(&io,&state));
  assert(state.ready && state.gate_polls==delays[delay]+RTL_PON_COLD_GATE_STABLE);
  assert(state.gate_stable==RTL_PON_COLD_GATE_STABLE && fifo_reads==4);
  assert(state.gate_written_mask==allowed && state.gate_sampled_mask==allowed);
  unchanged_except_gates();cases++;
 }
 /* Last-budget closure with too few consecutive samples still times out,
  * even though its last value is zero; no premature FIFO/fabric access. */
 for(unsigned target=0;target<4;target++)for(unsigned late=1;late<=3;late++) {
  setup(target<2?0x30f:0x30e,0xf,7,0);
  gate_delay[target]=RTL_PON_COLD_GATE_POLLS-RTL_PON_COLD_GATE_STABLE+late;
  assert(rtl_pon_cold_quiesce(&io,&state)==-ETIMEDOUT);
  assert(!state.ready && state.stage==RTL_PON_COLD_READBACK && !fifo_reads);
  assert(state.gate_polls==RTL_PON_COLD_GATE_POLLS && gate_waits==RTL_PON_COLD_GATE_POLLS-1);
  assert(state.gate_stable==RTL_PON_COLD_GATE_STABLE-late);
  assert(gate_writes[target]==1 && state.gate_written_mask==allowed);cases++;
 }
 /* A gate reopening between samples restarts the stable window. */
 for(unsigned target=0;target<4;target++) {
  setup(target<2?0x30f:0x30e,0xf,7,0);flicker_index=target;
  assert(!rtl_pon_cold_quiesce(&io,&state));
  assert(state.gate_polls==5 && gate_waits==4 && state.gate_stable==3);
  assert(state.gate_reopened_mask==(1U<<target));
  assert(state.gate_first_closed_poll[target]==1 && state.gate_changes[target]==3);
  assert(gate_writes[target]==1);unchanged_except_gates();cases++;
 }
 /* Already-disabled gates need observation, not gratuitous writes. */
 for(unsigned target=0;target<4;target++) {
  setup(target<2?0x30f:0x30e,0xf,7,0);
  regs[offsets[target]/4]&=~masks[target];saved[offsets[target]/4]=regs[offsets[target]/4];
  assert(!rtl_pon_cold_quiesce(&io,&state));
  assert(state.gate_sampled_mask==allowed && state.gate_written_mask==(allowed&~(1U<<target)));
  assert(!gate_writes[target] && state.gate_before[target]==state.gate_requested[target]);
  unchanged_except_gates();cases++;
 }
 /* Hardware may update unrelated fields during settling. The read-only
  * poll must retain that update and never replay the old full register. */
 for(unsigned target=0;target<4;target++)for(unsigned bit=0;bit<32;bit++)
 if(!(masks[target]&(1U<<bit)) && !(target==3 && bit>=30)) {
  setup(target<2?0x30f:0x30e,0xf,7,0x12345678);
  gate_delay[target]=2;change_index=target;change_wait=1;change_mask=1U<<bit;
  assert(!rtl_pon_cold_quiesce(&io,&state));
  unsigned expected=(saved[offsets[target]/4]&~masks[target])^change_mask;
  assert(regs[offsets[target]/4]==expected && state.gate_readback[target]==expected);
  assert(state.gate_requested[target]==(saved[offsets[target]/4]&~masks[target]));
  assert(gate_writes[target]==1 && state.gate_polls==5);cases++;
 }
 /* Stable-empty sampling must restart after a transient busy sample. */
 setup(0x30e,0x30000,3,0);fifo_flicker=1;
 assert(!rtl_pon_cold_quiesce(&io,&state));
 assert(fifo_reads==7 && waits==7);cases++;
 setup(0x30f,0x300ef,0x300,0);fifo_stuck=1;
 assert(rtl_pon_cold_quiesce(&io,&state)==-ETIMEDOUT);
 assert(fifo_reads==RTL_PON_COLD_FIFO_POLLS && waits==RTL_PON_COLD_FIFO_POLLS+2);
 assert(!state.ready && state.stage==RTL_PON_COLD_FIFO && state.refused_register==0x9010);
 unchanged_except_gates();cases++;
 /* An immediately reoccupied FIFO may not pass the final verify. */
 setup(0x30e,0x30000,3,0);verify_busy=1;
 assert(rtl_pon_cold_quiesce(&io,&state)==-EBUSY);
 assert(!state.ready && state.stage==RTL_PON_COLD_VERIFY && fifo_reads==4);cases++;
 /* The last verify FIFO sample must also be bracketed by the original
  * reset/mux values; checking only before it missed this transition. */
 for(unsigned target=0;target<3;target++)for(unsigned bit=0;bit<32;bit++) {
  setup(0x30e,0x30000,0x205,0);
  drift_fifo_read=4;drift_index=target;drift_mask=1U<<bit;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
  assert(!state.ready && state.stage==RTL_PON_COLD_VERIFY && fifo_reads==4);
  assert(state.refused_register==global_regs[target]);cases++;
 }
 for(unsigned target=0;target<4;target++)for(unsigned bit=0;bit<32;bit++)if(masks[target]&(1U<<bit)) {
  setup(target<2?0x30f:0x30e,0x300ef,0x307,0);
  stuck_index=target;stuck_mask=1U<<bit;
  assert(rtl_pon_cold_quiesce(&io,&state)==-ETIMEDOUT);
  assert(!state.ready && state.stage==RTL_PON_COLD_READBACK && !fifo_reads);
  assert(state.refused_register==offsets[target] && (state.refused_value&stuck_mask));
  assert(state.gate_polls==RTL_PON_COLD_GATE_POLLS && !state.gate_stable);
  assert(gate_waits==RTL_PON_COLD_GATE_POLLS-1 && gate_writes[target]==1);
  unsigned before=writes;
  assert(rtl_pon_cold_verify(&io,&state)==-ETIMEDOUT && writes==before);cases++;
 }
 /* All-ones MAC read fails before writing that missing register window. */
 for(unsigned target=0;target<4;target++) {
  setup(target<2?0x30f:0x30e,0x300ef,0x307,0);
  regs[offsets[target]/4]=~0U;saved[offsets[target]/4]=~0U;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
  assert(!state.ready && state.stage==RTL_PON_COLD_GATE && !fifo_reads);
  assert(regs[offsets[target]/4]==~0U && state.refused_register==offsets[target]);
  assert(state.gate_sampled_mask&(1U<<target));
  assert(!(state.gate_written_mask&(1U<<target)) && !gate_writes[target]);
  assert(state.gate_before[target]==~0U && state.gate_readback[target]==~0U);cases++;
 }
 /* Losing a register window after an apparently successful gate clear
  * is an I/O failure, never a reason to wait 1000 times or rewrite it. */
 const unsigned loss_reads[]={2,3,5};
 for(unsigned target=0;target<4;target++)for(unsigned loss=0;loss<3;loss++) {
  setup(target<2?0x30f:0x30e,0xf,7,0);
  ones_index=target;ones_on_read=loss_reads[loss];
  assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
  assert(!state.ready && state.refused_register==offsets[target] && state.refused_value==~0U);
  assert(state.gate_readback[target]==~0U && gate_reads[target]==loss_reads[loss]);
  assert(state.stage==(loss==2?RTL_PON_COLD_VERIFY:RTL_PON_COLD_READBACK));
  assert(fifo_reads==(loss==2?3U:0U) && gate_writes[target]==1);cases++;
 }
 for(unsigned loss=1;loss<=4;loss++) {
  setup(0x30e,0x30000,0x305,0);fifo_ones_on_read=loss;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
  assert(!state.ready && state.refused_register==0x9010 && state.refused_value==~0U);
  assert(state.stage==(loss==4?RTL_PON_COLD_VERIFY:RTL_PON_COLD_FIFO));
  assert(fifo_reads==loss && state.fifo_polls==loss);cases++;
 }
 for(unsigned target=0;target<3;target++) {
  setup(0x30e,0x30000,3,0);global[target]=~0U;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
  assert(state.stage==RTL_PON_COLD_GLOBAL && !writes && !mac_reads && !fifo_reads);
  assert(state.refused_register==global_regs[target]);cases++;
 }
 /* Torn or pre-gate snapshots reject before MAC MMIO. Never interpret
  * drift as a request to reselect another mode or release reset. */
 for(unsigned target=0;target<3;target++)for(unsigned bit=0;bit<32;bit++)
 for(unsigned when=2;when<=3;when++) {
  setup(0x30e,0x30000,3,0);
  drift_index=target;drift_mask=1U<<bit;drift_on_read=when;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
  assert(!state.ready && state.refused_register==global_regs[target]);
  if(when==2)assert(state.stage==RTL_PON_COLD_GLOBAL && !writes && !mac_reads && !fifo_reads);
  else assert(state.stage==RTL_PON_COLD_GATE && state.gated_mask==4 && !mac_reads && !writes);
  cases++;
 }
 /* Drift scheduled independently of read callbacks, at gate and FIFO
  * sleeps: every next access must check the global snapshot first. */
 for(unsigned target=0;target<3;target++)for(unsigned bit=0;bit<32;bit++)
 for(unsigned when=1;when<=4;when++) {
  setup(0x30e,0x30000,0x305,0);
  drift_index=target;drift_mask=1U<<bit;drift_on_wait=when;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
  assert(!state.ready && state.refused_register==global_regs[target]);
  assert(state.stage==(when<=2?RTL_PON_COLD_READBACK:RTL_PON_COLD_FIFO));
  assert(fifo_reads==(when<=2?0:when-2) && waits==when && gate_writes[3]==1);cases++;
 }
 /* Detect reset/mux drift caused after the first MAC sample BEFORE the
  * one-shot write. A sampled/requested value is not evidence of a write. */
 for(unsigned gate=0;gate<4;gate++)for(unsigned target=0;target<3;target++)
 for(unsigned bit=0;bit<32;bit++) {
  setup(gate<2?0x30f:0x30e,gate<2?(1U|(4U<<gate)):0,
        gate>=2?(1U|(2U<<(gate-2))):0,0x74638291);
  drift_index=target;drift_mask=1U<<bit;drift_mac_index=gate;drift_mac_read=1;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
  assert(!state.ready && state.stage==RTL_PON_COLD_GATE && !writes && !fifo_reads);
  assert(state.refused_register==global_regs[target] && state.gate_sampled_mask==(1U<<gate));
  assert(!state.gate_written_mask && state.gate_before[gate]==saved[offsets[gate]/4]);
  assert(state.gate_readback[gate]==saved[offsets[gate]/4]);
  assert(state.gate_requested[gate]==(saved[offsets[gate]/4]&~masks[gate]));cases++;
 }
 /* With two active children, revalidate between individual gate reads,
  * including the post-fabric strict verifier and its final FIFO read. */
 for(unsigned family=0;family<2;family++)for(unsigned child=0;child<2;child++)
 for(unsigned when=2;when<=5;when+=3)for(unsigned target=0;target<3;target++) {
  setup(family?0x30e:0x30f,0xf,7,0);
  drift_index=target;drift_mask=target?1:0x201;
  drift_mac_index=family*2+child;drift_mac_read=when;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
  assert(!state.ready && state.refused_register==global_regs[target]);
  assert(state.stage==(when==2?RTL_PON_COLD_READBACK:RTL_PON_COLD_VERIFY));
  assert(fifo_reads==(when==2?0U:3U));cases++;
 }
 /* Post-fabric verification rejects any reset/mux drift before MAC reads. */
 for(unsigned pdc=0;pdc<2;pdc++)for(unsigned target=0;target<3;target++)
 for(unsigned bit=0;bit<32;bit++) {
  setup(pdc?0x30e:0x00e,0x30000,3,0);
  assert(!rtl_pon_cold_quiesce(&io,&state));
  unsigned before_reads=mac_reads,before_writes=writes,before_fifo=fifo_reads;
  global[target]^=1U<<bit;
  assert(rtl_pon_cold_verify(&io,&state)==-EAGAIN);
  assert(!state.ready && state.stage==RTL_PON_COLD_VERIFY);
  assert(state.refused_register==global_regs[target]);
  assert(mac_reads==before_reads && writes==before_writes && fifo_reads==before_fifo);cases++;
 }
 for(unsigned target=0;target<4;target++) {
  setup(target<2?0x30f:0x30e,0x300ef,0x307,0);
  assert(!rtl_pon_cold_quiesce(&io,&state));
  regs[offsets[target]/4]|=masks[target];
  unsigned before_writes=writes,before_waits=waits,before_polls=state.gate_polls;
  assert(rtl_pon_cold_verify(&io,&state)==-EIO);
  assert(!state.ready && state.refused_register==offsets[target]);
  assert(writes==before_writes && waits==before_waits && state.gate_polls==before_polls);cases++;
 }
 setup(0x30e,0x30000,3,0);assert(!rtl_pon_cold_quiesce(&io,&state));fifo_stuck=1;
 assert(rtl_pon_cold_verify(&io,&state)==-EBUSY && !state.ready);cases++;
 struct rtl_dq_io bad={0};
 assert(rtl_pon_cold_quiesce(NULL,&state)==-EINVAL);
 assert(rtl_pon_cold_quiesce(&bad,&state)==-EINVAL);
 assert(rtl_pon_cold_quiesce(&io,NULL)==-EINVAL);
 assert(rtl_pon_cold_verify(NULL,&state)==-EINVAL);
 assert(rtl_pon_cold_verify(&bad,&state)==-EINVAL);
 assert(rtl_pon_cold_verify(&io,NULL)==-EINVAL);
 state=(struct rtl_pon_cold_state){0};
 assert(rtl_pon_cold_verify(&io,&state)==-EAGAIN);
 printf("PASS: cold PON owner: %u reset/mux/reserved/fault cases; no inactive MMIO, GPIO, BOSA, TX or GLOBAL writes\n",cases);
 return 0;
}
'''

LEGACY_CASE = r'''
int main(void) {
 struct rtl_pon_cold_state state={0};sdk_oracle();
 (void)unchanged_except_gates;
 setup(0x30e,0x30000,0x305,0);
 regs[0x4004/4]=saved[0x4004/4]=0xa2;gate_delay[3]=2;
 assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
 assert(!state.ready && state.stage==RTL_PON_COLD_READBACK);
 assert(state.gated_mask==8 && state.refused_register==0x4004 && state.refused_value==0xa2);
 assert(writes==1 && gate_writes[3]==1 && gate_reads[3]==2 && !waits && !fifo_reads);
 /* Advance the backend, not the old helper. It would acknowledge the
  * original write without any retry; the original helper already refused. */
 usleep_range(100,200);usleep_range(100,200);
 assert(regs[0x4004/4]==0xa0 && writes==1 && !fifo_reads && !state.ready);
 puts("PASS: actual baseline helper rejects the synthetic delayed gate; the same single request settles after two modeled intervals");
}
'''


def change_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Mutation target not unique: ' + repr(old))
    return source.replace(old, new, 1)


def change_function(source, name, old, new):
    match = re.search(r'\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', source)
    if not match:
        raise ValueError('Missing mutation function ' + name)
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return (source[:match.start()] +
            change_once(source[match.start():end], old, new) + source[end:])


def variants(header):
    yield 'production', header
    mutations = (
        ('wrong_gpon_bit', '0x6114U, 1U << 1', '0x6114U, 1U << 2'),
        ('partial_xgpon_field', '0x4004U, 3U', '0x4004U, 1U'),
        ('inverted_mux', 'if (state->control & RTL_PON_COLD_EPON_MODE)',
         'if (!(state->control & RTL_PON_COLD_EPON_MODE))'),
        ('wrong_pdc_reset_polarity', 'state->pdc_active = !!(state->control & RTL_PON_COLD_PDC_RELEASED)',
         'state->pdc_active = !(state->control & RTL_PON_COLD_PDC_RELEASED)'),
        ('read_fifo_in_reset', 'if (state->pdc_active) {', 'if (1) {'),
        ('miss_active_ethernet', 'RTL_PON_COLD_ACTIVE_ETH_RELEASED |',
         '0U |'),
        ('skip_initial_snapshot_verify', 'ret = rtl_pon_cold_globals_match(io, state);\n\tif (ret)\n\t\treturn ret;\n\tstate->pdc_active',
         'ret = 0; (void)ret;\n\tstate->pdc_active'),
        ('ignore_snapshot_drift', 'if (value != state->member)', 'if (0)'),
        ('access_every_family', 'state->stage = RTL_PON_COLD_GATE;',
         'state->gated_mask = 15U;\n\tstate->stage = RTL_PON_COLD_GATE;'),
        ('clobber_reserved_bits', 'state->gate_requested[i] = value & ~rtl_pon_cold_gates[i].mask;',
         'state->gate_requested[i] = 0;'),
        ('accept_single_closed_gate', '#define RTL_PON_COLD_GATE_STABLE 3U',
         '#define RTL_PON_COLD_GATE_STABLE 1U'),
        ('accept_single_empty', '#define RTL_PON_COLD_FIFO_STABLE 3U',
         '#define RTL_PON_COLD_FIFO_STABLE 1U'),
        ('ignore_fifo_timeout', 'if (i == RTL_PON_COLD_FIFO_POLLS)',
         'if (0)'),
        ('allow_xgpon_command_replay',
         'if (gate == RTL_PON_COLD_GATE_XGPON && (value & RTL_PON_COLD_XGPON_COMMANDS))',
         'if (0 && gate == RTL_PON_COLD_GATE_XGPON && (value & RTL_PON_COLD_XGPON_COMMANDS))'),
        ('observe_held_reset_pdc', 'if (!(control & RTL_PON_COLD_PDC_RELEASED))',
         'if (0 && !(control & RTL_PON_COLD_PDC_RELEASED))'),
        ('observe_held_reset_psds', '!(control & RTL_PON_COLD_PSDS_CSR_RELEASED))',
         '0 && !(control & RTL_PON_COLD_PSDS_CSR_RELEASED))'),
    )
    for name, old, new in mutations:
        yield name, change_once(header, old, new)
    guarded_read = ('ret = rtl_pon_cold_globals_match(io, state);\n'
                    '\t\t\tif (ret)\n\t\t\t\treturn ret;\n'
                    '\t\t\tvalue = io->read(io->context, rtl_pon_cold_gates[i].reg);')
    guarded_fifo = ('ret = rtl_pon_cold_clock_check(io, state);\n'
                    '\t\tif (ret)\n\t\t\treturn ret;\n'
                    '\t\tret = rtl_pon_cold_globals_match(io, state);\n'
                    '\t\tif (ret)\n\t\t\treturn ret;\n'
                    '\t\tvalue = io->read(io->context, RTL_PON_COLD_PDC_FIFO_STATUS);')
    scoped = (
        ('ignore_missing_mac', 'rtl_pon_cold_quiesce',
         'state->gate_readback[i] = value;\n\t\tif (value == ~0U)',
         'state->gate_readback[i] = value;\n\t\tif (0)'),
        ('skip_post_fabric_mac_check', 'rtl_pon_cold_verify',
         'if (value & rtl_pon_cold_gates[i].mask)', 'if (0)'),
        ('immediate_readback_regression', 'rtl_pon_cold_wait_gates',
         'if (value & rtl_pon_cold_gates[i].mask) {\n\t\t\t\tclosed = 0;',
         'if (value & rtl_pon_cold_gates[i].mask) {\n'
         '\t\t\t\treturn rtl_pon_cold_error(state, -EIO, rtl_pon_cold_gates[i].reg, value);'),
        ('ignore_missing_settling_gate', 'rtl_pon_cold_wait_gates',
         'if (value == ~0U)', 'if (0)'),
        ('do_not_restart_gate_stability', 'rtl_pon_cold_wait_gates',
         'closed ? state->gate_stable + 1 : 0',
         'closed ? state->gate_stable + 1 : state->gate_stable'),
        ('replay_gate_write_during_wait', 'rtl_pon_cold_wait_gates',
         'state->gate_readback[i] = value;',
         'io->write(io->context, rtl_pon_cold_gates[i].reg, state->gate_requested[i]);\n'
         '\t\t\tstate->gate_readback[i] = value;'),
        ('skip_settling_global_guards', 'rtl_pon_cold_wait_gates',
         guarded_read, 'ret = 0; (void)ret;\n\t\t\tvalue = io->read(io->context, rtl_pon_cold_gates[i].reg);'),
        ('skip_prewrite_global_guard', 'rtl_pon_cold_quiesce',
         'ret = rtl_pon_cold_globals_match(io, state);\n\t\t\tif (ret)\n\t\t\t\treturn ret;\n'
         '\t\t\tio->write(io->context, rtl_pon_cold_gates[i].reg,',
         'io->write(io->context, rtl_pon_cold_gates[i].reg,'),
        ('skip_fifo_global_guards', 'rtl_pon_cold_quiesce',
         guarded_fifo, 'value = io->read(io->context, RTL_PON_COLD_PDC_FIFO_STATUS);'),
        ('skip_verify_fifo_global_guard', 'rtl_pon_cold_verify',
         guarded_fifo, 'value = io->read(io->context, RTL_PON_COLD_PDC_FIFO_STATUS);'),
        ('ignore_missing_fifo', 'rtl_pon_cold_quiesce',
         'state->fifo_polls++;\n\t\tif (value == ~0U)',
         'state->fifo_polls++;\n\t\tif (0)'),
        ('ignore_missing_verify_fifo', 'rtl_pon_cold_verify',
         'state->fifo_polls++;\n\t\tif (value == ~0U)',
         'state->fifo_polls++;\n\t\tif (0)'),
        ('skip_verify_final_global_guard', 'rtl_pon_cold_verify',
         'ret = rtl_pon_cold_globals_match(io, state);\n\tif (ret)\n\t\treturn ret;\n\tstate->stage = RTL_PON_COLD_READY;',
         'state->stage = RTL_PON_COLD_READY;'),
        ('skip_snapshot_final_global_guard', 'rtl_pon_cold_snapshot',
         'for (j = 0; j < RTL_PON_COLD_SAMPLE_PSDS_MODE; j++) {\n\t\tvalue =',
         'for (j = 0; j < RTL_PON_COLD_SAMPLE_PSDS_MODE && 0; j++) {\n\t\tvalue ='),
    )
    for name, symbol, old, new in scoped:
        yield name, change_function(header, symbol, old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registers', type=Path)
    parser.add_argument('--sdk-directory', type=Path)
    parser.add_argument('--baseline-git', help='Also run the actual old header from this local git revision on the two-interval oracle')
    args = parser.parse_args()
    sdk_sources(args.sdk_directory)
    oracle = sdk_oracle(args.registers)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    mutants = 0
    with tempfile.TemporaryDirectory(prefix='pon-cold-') as temp:
        directory = Path(temp)
        compat = directory / 'compat'
        if sys.platform == 'darwin':
            (compat / 'linux').mkdir(parents=True)
            (compat / 'linux/errno.h').write_text('#include <errno.h>\n')
        units = [(name, header, SHIM + oracle + CASES) for name, header in variants(HEADER.read_text())]
        if args.baseline_git:
            old = subprocess.run(['git', 'show', args.baseline_git + ':' + str(HEADER.relative_to(ROOT))],
                                 cwd=ROOT, text=True, capture_output=True, check=True).stdout
            units.insert(0, ('baseline', old, SHIM.split('static void valid_case(', 1)[0] + oracle + LEGACY_CASE))
        for name, header, unit in units:
            target = directory / name
            target.mkdir()
            (target / HEADER.name).write_text(header)
            source, binary = target / 'test.c', target / 'test'
            source.write_text(unit)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                                    '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                    '-fno-omit-frame-pointer',
                                    *([] if sys.platform == 'darwin' else ['-no-pie']),
                                    '-I', str(compat), '-I', str(target), '-I', str(DRIVER),
                                    str(source), '-o', str(binary)],
                                   capture_output=True, text=True)
            if build.returncode:
                raise SystemExit(f'{name}: compile failed\n' + build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45,
                                 env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0',
                                      'UBSAN_OPTIONS': 'halt_on_error=1'})
            if name in ('production', 'baseline'):
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                print(run.stdout, end='')
            else:
                if run.returncode == 0:
                    raise SystemExit(f'SURVIVED: {name}')
                # An instrumentation crash, UB or timeout is a broken test,
                # not proof that the intended safety mutant was detected.
                if (run.returncode != -signal.SIGABRT or 'assert' not in run.stderr.lower() or
                        'AddressSanitizer' in run.stderr or 'runtime error:' in run.stderr):
                    raise SystemExit(f'{name}: not rejected by a runtime assertion\n' + run.stderr)
                if name == 'immediate_readback_regression' and not any(marker in run.stderr for marker in (
                        '!rtl_pon_cold_quiesce(&io,&state)', 'rtl_pon_cold_quiesce(&io,&state)==-ETIMEDOUT')):
                    raise SystemExit('Old readback did not fail the intended delayed-acknowledgement assertion\n' + run.stderr)
                mutants += 1
    print(f'PASS: rejected {mutants} cold-handoff safety mutants by runtime assertions; ASan/UBSan enabled')


if __name__ == '__main__':
    main()
