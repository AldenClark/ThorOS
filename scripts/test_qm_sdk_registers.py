#!/usr/bin/env python3
"""Decode native QM/DQ setup using independently supplied RTL77C SDK declarations.

Reviewed references: GPL-for-GP3000 5090fbcb rtl8277c_registers.h (silicon,
not FPGA) and ca-network-drivers 8b4f4882 aal-77c/aal_l3qm.c. The external
bitfields, addresses and buffer-size decoder are extracted at runtime rather
than reimplemented in a mock. This verifies encoding, not live AXI coherency,
credits, queue scheduling or throughput. Both paths are required explicitly.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sdk-header', type=Path, required=True)
parser.add_argument('--sdk-qm', type=Path, required=True)
args = parser.parse_args()
for path, expected in (
    (args.sdk_header, 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0'),
    (args.sdk_qm, 'afd977c54889b62866a90f484169de2971301ba93283a3a3c3a11b13cc73720a'),
):
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise SystemExit(f'SDK pin mismatch: {path.name}: {observed}; expected {expected}')
root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
sdk = args.sdk_header.read_text()
source = (drivers / 'rtl9617c-qm.c').read_text()


def declaration(name):
    end = sdk.index('} ' + name + ';') + len('} ' + name + ';')
    start = sdk.rfind('typedef volatile union {', 0, end)
    assert start >= 0
    return sdk[start:end] + '\n'


def function(text, name):
    start = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{', text, re.M).start()
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'


names = [f'QM_QM_CFG{i}_EQ0_t' for i in range(5)] + [
    'QM_QM_EQ_PROFILE0_t', 'QM_QM_DEST_PORT0_EQ_CFG_t',
    'QM_QM_DEST_PORT0_PKT_BUF_CFG_t', 'QM_QM_BUFFER_CNTL_t',
    'QM_QM_UPPER_LDPID_MAP_t', 'QM_QM_CPU_EPP_FIFO_CFG_profile0_t',
    'QM_QM_CPU_EPP_FIFO0_0_CFG_t', 'QM_QM_AXI_ATTRIBUTE_DATA0_t',
    'QM_QM_AXI_ATTRIBUTE_DATA1_t', 'QM_QM_AXI_ATTRIBUTE_ACCESS_t',
    'TE_CB_PORT_THRSH_PROFILE0_t', 'TE_CB_PORT_FREECNT_MEM_DATA_t',
    'TE_CB_VOQ_THRSH_PROFILE_MEM_DATA0_t',
    'TE_CB_VOQ_THRSH_PROFILE_MEM_DATA1_t',
    'TE_CB_VOQ_THRSH_PROFILE_MEM_DATA2_t']
declarations = ''.join(declaration(name) for name in names)
addresses = {
    'QM_QM_CFG0_EQ0': 0x61e8, 'QM_QM_EQ_PROFILE0': 0x6128,
    'QM_QM_DEST_PORT0_EQ_CFG': 0x6148, 'QM_QM_DEST_PORT0_PKT_BUF_CFG': 0x61c8,
    'QM_QM_CPU_EPP_FIFO_CFG_profile0': 0x657c, 'QM_QM_CPU_EPP_FIFO0_0_CFG': 0x65a4,
    'QM_QM_AXI_ATTRIBUTE_ACCESS': 0x66a4, 'QM_QM_AXI_ATTRIBUTE_DATA1': 0x66a8,
    'QM_QM_AXI_ATTRIBUTE_DATA0': 0x66ac,
    'QM_QM_CPUEPP_POINTER_CPUEPP64_FIFO_WRPTR': 0x7000,
    'QM_QM_CPUEPP_POINTER_CPUEPP64_FIFO_RDPTR': 0x7100,
    'QM_QM_CPUEPP_POINTER_CPUEPP64_FIFO_PADDR_START': 0x7200,
    'TE_CB_PORT_THRSH_PROFILE0': 0x9580, 'TE_CB_PORT_FREECNT_MEM_ACCESS': 0x95a8,
    'TE_CB_VOQ_THRSH_PROFILE_MEM_ACCESS': 0x95b0,
    'TE_CB_VOQ_THRSH_SELECT_MEM_ACCESS': 0x95c0}
for name, offset in addresses.items():
    actual = int(re.search(r'^#define ' + name + r'\s+(0x[0-9a-fA-F]+)\s*$', sdk, re.M)[1], 16)
    assert actual == 0xf4300000 + offset, (name, hex(actual), hex(offset))

fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint32_t ca_uint32_t;
typedef uint8_t ca_uint8_t;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define printk(...) ((void)0)
#define RTL_QM_RING_BYTES 1024
#define RTL_QM_VOQS 8
#define RTL_QM_BUFFERS_PER_EQ 256
#define EQ_ID 4
#define EQ_CFG (0x61e8 + EQ_ID * 20)
#define EQ_PROFILE (0x6128 + EQ_ID * 4)
#define EPP_BASE 0x7200
#include "rtl9617c-qm-deepq.h"
#include "rtl9617c-qm-layout.h"
struct rtl_qm_rx {void *ni;unsigned ring_dma;};
static u32 regs[65536/4],attributes[64][2],profiles[8][3],credits[32],voq[256];
static u32 readl(void *p){return *(u32 *)p;}
static void writel(u32 v,void *p){
 unsigned r=(char *)p-(char *)regs,index=v&255;
 assert(r<65536 && !(r&3));
 switch(r) {
 case 0x66a4:assert(index<64);attributes[index][0]=regs[0x66ac/4];attributes[index][1]=regs[0x66a8/4];break;
 case 0x95a8:assert(index<32);credits[index]=regs[0x95ac/4];break;
 case 0x95b0:assert(index<8);profiles[index][0]=regs[0x95bc/4];profiles[index][1]=regs[0x95b8/4];profiles[index][2]=regs[0x95b4/4];break;
 case 0x95c0:voq[index]=regs[0x95c4/4];break;
 default:*(u32 *)p=v;return;
 }
 assert((v&(BIT(31)|BIT(30)))==(BIT(31)|BIT(30)));*(u32 *)p=v&~BIT(31);
}
#define readl_poll_timeout(p,v,condition,delay,timeout) ({(v)=readl(p);(condition)?0:-ETIMEDOUT;})
'''
production = ''.join(function(source, name) for name in (
    'rtl_qm_window_idle', 'rtl_qm_indirect', 'rtl_qm_attribute',
    'rtl_qm_cpu_credits', 'rtl_dq_read', 'rtl_dq_write', 'rtl_dq_indirect'))
production += function(args.sdk_qm.read_text(), 'aal_l3qm_get_buffer_size_index')
eq_start = source.index('\t/* Distinct EQ4/EQ5:')
eq_end = source.index('\tret = rtl_qm_deepq_prepare(', eq_start)
epp_start = source.index('\twritel(0, ni + 0x6558);')
epp_end = source.index('\tfor (i = 0; i < RTL_QM_BUFFERS; i++)', epp_start)
production += 'static void cpu_setup(struct rtl_qm_rx *rx) { void *ni=rx->ni;unsigned i;\n'
production += source[eq_start:eq_end] + source[epp_start:epp_end] + '}\n'
cases = r'''
int main(void) {
 struct rtl_qm_rx rx={.ni=regs,.ring_dma=0x06000000};
 const struct rtl_dq_io io={&rx,rtl_dq_read,rtl_dq_write,rtl_dq_indirect};
 regs[0x68b0/4]=~0U;regs[0x610c/4]=~0U;
 assert(!rtl_qm_deepq_prepare(&io,0x12000000));
 assert(!(regs[0x610c/4]&0xffff));
 for(unsigned pool=0;pool<2;pool++) {
  unsigned cfg=(0x61e8+(pool+1)*20)/4;
  QM_QM_CFG0_EQ0_t a={.wrd=regs[cfg]};
  QM_QM_CFG1_EQ0_t b={.wrd=regs[cfg+1]};
  QM_QM_CFG2_EQ0_t c={.wrd=regs[cfg+2]};
  QM_QM_CFG3_EQ0_t d={.wrd=regs[cfg+3]};
  QM_QM_CFG4_EQ0_t e={.wrd=regs[cfg+4]};
  assert(a.bf.eq_en && ((unsigned)a.bf.phy_addr_start<<7)==0x12000000U+pool*512*2048);
  assert(b.bf.bid_start==512+pool*512 && b.bf.total_buffer_num==512);
  assert(c.bf.buffer_size==aal_l3qm_get_buffer_size_index(2048) && !c.bf.cpu_eq && !c.bf.refill_en);
  assert(d.bf.cache==6 && d.bf.domain==2 && !d.bf.snoop && d.bf.acd_cmd && d.bf.cache_eos==6);
  assert(e.bf.axi_top_bit==2);
 }
 QM_QM_EQ_PROFILE0_t profile={.wrd=regs[0x612c/4]};
 QM_QM_UPPER_LDPID_MAP_t map={.wrd=regs[0x68f8/4]};
 QM_QM_BUFFER_CNTL_t buffer={.wrd=regs[0x68b0/4]};
 TE_CB_PORT_THRSH_PROFILE0_t port={.wrd=regs[0x958c/4]};
 assert(profile.bf.eqp0==1 && profile.bf.eqp1==2 && !profile.bf.rule);
 assert(map.bf.pon_en && map.bf.pon_offset==2 && !buffer.bf.jumbo_buffer_en && !buffer.bf.alternate_eq_en);
 assert(port.bf.lth==512*2/3 && port.bf.hth==(512*2/3)*2);
 TE_CB_VOQ_THRSH_PROFILE_MEM_DATA0_t th0={.wrd=profiles[3][0]};
 TE_CB_VOQ_THRSH_PROFILE_MEM_DATA1_t th1={.wrd=profiles[3][1]};
 TE_CB_VOQ_THRSH_PROFILE_MEM_DATA2_t th2={.wrd=profiles[3][2]};
 assert(th0.bf.lth==512*2/3 && th0.bf.hth==512);
 assert((th1.bf.grplth<<4|th0.bf.grplth)==16383 && th1.bf.grphth==16383);
 assert((th2.bf.prvt<<8|th1.bf.prvt)==25);
 for(unsigned p=16;p<32;p++) {
  QM_QM_DEST_PORT0_EQ_CFG_t dest={.wrd=regs[(0x6148+p*4)/4]};
  TE_CB_PORT_FREECNT_MEM_DATA_t credit={.wrd=credits[p]};
  assert(dest.bf.profile_sel==1 && credit.bf.cnt0==512 && credit.bf.cnt1==512 && credit.bf.cnt0_msb && credit.bf.cnt1_msb);
  for(unsigned q=p*8;q<p*8+8;q++)assert(voq[q]==3);
 }
 regs[(0x657c+4*4)/4]=0xe0008001;cpu_setup(&rx);
 for(unsigned pool=0;pool<2;pool++) {
  unsigned cfg=(0x61e8+(pool+4)*20)/4;
  QM_QM_CFG1_EQ0_t b={.wrd=regs[cfg+1]};QM_QM_CFG2_EQ0_t c={.wrd=regs[cfg+2]};
  assert(b.bf.bid_start==pool*256 && b.bf.total_buffer_num==256 && c.bf.cpu_eq);
  assert(c.bf.buffer_size==aal_l3qm_get_buffer_size_index(2048) && !c.bf.refill_en && c.bf.refill_ths==24);
 }
 QM_QM_CPU_EPP_FIFO_CFG_profile0_t fifo={.wrd=regs[(0x657c+4*4)/4]};
 assert(fifo.bf.size*16==1024 && fifo.bf.high_ths==2 && fifo.bf.timer_ths==15 && fifo.bf.max_buf_cnt_per_pkt==7);
 for(unsigned q=0;q<8;q++) {
  QM_QM_CPU_EPP_FIFO0_0_CFG_t config={.wrd=regs[(0x65a4+q*4)/4]};
  assert(config.bf.profile_sel==4 && regs[(0x7200+q*4)/4]==0x06000000+q*1024);
 }
 assert(!rtl_qm_cpu_credits(&rx));
 port.wrd=regs[0x9580/4];assert(port.bf.lth==4 && port.bf.hth==32);
 th0.wrd=profiles[0][0];assert(th0.bf.lth==192 && th0.bf.hth==224);
 for(unsigned q=0;q<8;q++)assert(voq[q]==0);
 /* Dirty upper DATA1 bits must not leak into an otherwise correct 0x02 alias. */
 regs[0x66a8/4]=3;assert(!rtl_qm_attribute(&rx,48,0x0a008060));
 QM_QM_AXI_ATTRIBUTE_DATA0_t attr0={.wrd=attributes[48][0]};
 QM_QM_AXI_ATTRIBUTE_DATA1_t attr1={.wrd=attributes[48][1]};
 assert((attr0.bf.axi_top_bit|(attr1.bf.axi_top_bit<<6))==2);
 assert(attr0.bf.ace_cmd && attr0.bf.cache==6 && attr0.bf.domain==2 && !attr0.bf.snoop);
 puts("RTL77C SDK QM oracle: addresses, disjoint CPU/DQ EQs, 2KiB decoder, AXI prefix, CPU EPP ring/coalescing and 16-port/128-VOQ thresholds match silicon declarations");
}
'''
with tempfile.TemporaryDirectory(prefix='qm-sdk-', dir=root / 'artifacts') as temp:
    c, exe = Path(temp) / 'test.c', Path(temp) / 'test'
    c.write_text(fixture + declarations + production + cases)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(drivers), '-I',
                    str(root / 'port/overlay/target/linux/rtl9617c/files-6.18/include/linux'),
                    str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
