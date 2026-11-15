#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the production NI-owned PON cold fence with reset-aware MMIO faults.

The model rejects every access to a held-reset or unselected MAC and to a
held-reset PDC FIFO. Optional generated-register and GPL source pins check
the actual vendor field layouts and reset polarity; this is not a hardware
clock, bus-response, optical, or DDR-retirement proof.

--sdk-directory accepts a pinned ca-network-drivers checkout root or its
ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c directory.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import resource
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
    for name in [*(r[0] for r in gates.values()), *globals_, 'PDC_FIFO_STATUS']:
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
            output += f'{{ {register}_t word={{.wrd=0}}; word.bf.{field}=1; assert(word.wrd=={mask}); }}\n'
    output += '''
 assert(RTL_PON_COLD_CONTROL==GLOBAL_PON_CNTL);
 assert(RTL_PON_COLD_EPON_CONTROL==GLOBAL_EPON_CNTL);
 assert(RTL_PON_COLD_GPON_CONTROL==GLOBAL_GPON_CNTL);
 PDC_FIFO_STATUS_t fifo={.wrd=~0U}; fifo.bf.depth=0;
 assert(RTL_PON_COLD_PDC_FIFO_STATUS==PDC_FIFO_STATUS-0xf5500000U);
 assert(fifo.wrd==~RTL_PON_COLD_PDC_FIFO_DEPTH);
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
static void usleep_range(unsigned low,unsigned high) {
 assert(low==100 && high==200);waits++;
}
#include "rtl9617c-pon-cold.h"
static unsigned regs[0xc000/4],saved[0xc000/4],global[3],initial[3],global_reads[3];
static const unsigned offsets[]={0x088c,0x10b4,0x6114,0x4004};
static const unsigned masks[]={1U,1U<<7,1U<<1,3U};
static const unsigned global_regs[]={0xf4320094U,0xf4320074U,0xf432007cU};
static unsigned allowed,mac_reads,writes,fifo_reads,busy_left,stuck_index,stuck_mask;
static unsigned drift_index,drift_on_read,drift_mask;
static int expected_error,fifo_stuck,fifo_flicker,verify_busy;
static unsigned read_reg(void *ctx,unsigned reg) {
 (void)ctx;
 for(unsigned i=0;i<3;i++)if(reg==global_regs[i]) {
  global_reads[i]++;
  if(drift_index==i && global_reads[i]==drift_on_read)global[i]^=drift_mask;
  return global[i];
 }
 /* Reject access to every held-reset PDC or unsupported/ambiguous mode. */
 assert((initial[0]&0x200) && !expected_error);
 if(reg==0x9010) {
  for(unsigned i=0;i<4;i++)if(allowed&(1U<<i))assert(!(regs[offsets[i]/4]&masks[i]));
  fifo_reads++;
  if(fifo_stuck || (verify_busy && fifo_reads>=4))return 0xc001;
  if(busy_left){busy_left--;return 0xc001;}
  if(fifo_flicker && fifo_reads==3)return 0xc001;
  return 0xc000;
 }
 for(unsigned i=0;i<4;i++)if(reg==offsets[i]) {
  /* This is an access fault, not a benign zero-filled inactive register. */
  assert(allowed&(1U<<i));mac_reads++;return regs[reg/4];
 }
 assert(!"unexpected register read");return 0;
}
static void write_reg(void *ctx,unsigned reg,unsigned value) {
 (void)ctx;unsigned i;
 for(i=0;i<4;i++)if(reg==offsets[i])break;
 /* GLOBAL, TX, reset and unrelated registers must NEVER be written. */
 assert(i<4 && (allowed&(1U<<i)));
 assert(regs[reg/4]!=~0U);
 assert((value&~masks[i])==(saved[reg/4]&~masks[i]));
 assert(!(value&masks[i]));
 regs[reg/4]=value;writes++;
 if(i==stuck_index)regs[reg/4]|=stuck_mask;
}
static const struct rtl_dq_io io={.read=read_reg,.write=write_reg};
static void setup(unsigned control,unsigned epon,unsigned gpon,unsigned seed) {
 global[0]=control;global[1]=epon;global[2]=gpon;
 memcpy(initial,global,sizeof(global));memset(global_reads,0,sizeof(global_reads));
 for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i++)regs[i]=(i*2654435761U)^seed;
 for(unsigned i=0;i<4;i++)regs[offsets[i]/4]|=masks[i];
 memcpy(saved,regs,sizeof(regs));
 writes=mac_reads=fifo_reads=busy_left=waits=0;allowed=0;expected_error=0;
 fifo_stuck=fifo_flicker=verify_busy=0;stuck_index=4;stuck_mask=0;
 drift_index=3;drift_on_read=0;drift_mask=0;
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
 assert(state->pdc_active==!!(initial[0]&0x200));
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
int main(void) {
 struct rtl_pon_cold_state state={0};unsigned cases=0;
 sdk_oracle();
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
  if(initial[0]&0x200)assert(fifo_reads==n+5 && waits==n+2);
  cases++;
 }
 /* Stable-empty sampling must restart after a transient busy sample. */
 setup(0x30e,0x30000,3,0);fifo_flicker=1;
 assert(!rtl_pon_cold_quiesce(&io,&state));
 assert(fifo_reads==7 && waits==5);cases++;
 setup(0x30f,0x300ef,0x300,0);fifo_stuck=1;
 assert(rtl_pon_cold_quiesce(&io,&state)==-ETIMEDOUT);
 assert(fifo_reads==RTL_PON_COLD_FIFO_POLLS && waits==RTL_PON_COLD_FIFO_POLLS);
 assert(!state.ready && state.stage==RTL_PON_COLD_FIFO && state.refused_register==0x9010);
 unchanged_except_gates();cases++;
 /* An immediately reoccupied FIFO may not pass the final verify. */
 setup(0x30e,0x30000,3,0);verify_busy=1;
 assert(rtl_pon_cold_quiesce(&io,&state)==-EBUSY);
 assert(!state.ready && state.stage==RTL_PON_COLD_VERIFY && fifo_reads==4);cases++;
 for(unsigned target=0;target<4;target++)for(unsigned bit=0;bit<32;bit++)if(masks[target]&(1U<<bit)) {
  setup(target<2?0x30f:0x30e,0x300ef,0x307,0);
  stuck_index=target;stuck_mask=1U<<bit;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
  assert(!state.ready && state.stage==RTL_PON_COLD_READBACK && !fifo_reads);
  assert(state.refused_register==offsets[target] && (state.refused_value&stuck_mask));cases++;
 }
 /* All-ones MAC read fails before writing that missing register window. */
 for(unsigned target=0;target<4;target++) {
  setup(target<2?0x30f:0x30e,0x300ef,0x307,0);
  regs[offsets[target]/4]=~0U;saved[offsets[target]/4]=~0U;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
  assert(!state.ready && state.stage==RTL_PON_COLD_GATE && !fifo_reads);
  assert(regs[offsets[target]/4]==~0U && state.refused_register==offsets[target]);cases++;
 }
 for(unsigned target=0;target<3;target++) {
  setup(0x30e,0x30000,3,0);global[target]=~0U;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EIO);
  assert(state.stage==RTL_PON_COLD_GLOBAL && !writes && !mac_reads && !fifo_reads);
  assert(state.refused_register==global_regs[target]);cases++;
 }
 /* Torn initial snapshots reject before MAC MMIO; later drift fails final
  * verification. Never interpret drift as a request to reselect a family. */
 for(unsigned target=0;target<3;target++)for(unsigned bit=0;bit<32;bit++)
 for(unsigned when=2;when<=3;when++) {
  setup(0x30e,0x30000,3,0);
  drift_index=target;drift_mask=1U<<bit;drift_on_read=when;
  assert(rtl_pon_cold_quiesce(&io,&state)==-EAGAIN);
  assert(!state.ready && state.refused_register==global_regs[target]);
  if(when==2)assert(state.stage==RTL_PON_COLD_GLOBAL && !writes && !mac_reads && !fifo_reads);
  else assert(state.stage==RTL_PON_COLD_VERIFY && state.gated_mask==4);
  cases++;
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
  assert(rtl_pon_cold_verify(&io,&state)==-EIO);
  assert(!state.ready && state.refused_register==offsets[target]);cases++;
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


def change_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Mutation target not unique: ' + repr(old))
    return source.replace(old, new, 1)


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
        ('ignore_missing_mac', '\t\tif (value == ~0U)\n', '\t\tif (0)\n'),
        ('clobber_reserved_bits', 'value & ~rtl_pon_cold_gates[i].mask);', '0);'),
        ('accept_single_empty', '#define RTL_PON_COLD_FIFO_STABLE 3U',
         '#define RTL_PON_COLD_FIFO_STABLE 1U'),
        ('ignore_fifo_timeout', 'if (i == RTL_PON_COLD_FIFO_POLLS)',
         'if (0)'),
        ('skip_post_fabric_mac_check',
         'if (value & rtl_pon_cold_gates[i].mask)\n\t\t\treturn rtl_pon_cold_error(state, -EIO,',
         None),
    )
    for name, old, new in mutations:
        if name == 'skip_post_fabric_mac_check':
            # The first match is verify; the second is the pre-FIFO readback.
            assert header.count(old) == 2
            yield name, header.replace(old, 'if (0)\n\t\t\treturn rtl_pon_cold_error(state, -EIO,', 1)
        else:
            yield name, change_once(header, old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registers', type=Path)
    parser.add_argument('--sdk-directory', type=Path)
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
        for name, header in variants(HEADER.read_text()):
            target = directory / name
            target.mkdir()
            (target / HEADER.name).write_text(header)
            source, binary = target / 'test.c', target / 'test'
            source.write_text(SHIM + oracle + CASES)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                                    '-Wall', '-Wextra', '-Werror',
                                    '-I', str(compat), '-I', str(target), '-I', str(DRIVER),
                                    str(source), '-o', str(binary)],
                                   capture_output=True, text=True)
            if build.returncode:
                raise SystemExit(f'{name}: compile failed\n' + build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45)
            if name == 'production':
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                print(run.stdout, end='')
            else:
                if run.returncode == 0:
                    raise SystemExit(f'SURVIVED: {name}')
                mutants += 1
    print(f'PASS: rejected {mutants} cold-handoff safety mutants')


if __name__ == '__main__':
    main()
