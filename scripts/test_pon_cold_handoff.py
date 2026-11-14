#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the production cold PON RX fence and NI handoff ordering with faults.

Optional --registers checks fields and addresses using the pinned RTL8277C
generated unions. This is a host MMIO model, not an optical or drain proof.
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
SOURCE = DRIVER / 'rtl9617c-pon.c'
SDK_SHA = 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0'


def function(source, name):
    match = re.search(r'^static [^\n]*\b' + re.escape(name) + r'\(', source, re.M)
    if not match:
        raise ValueError('Missing production function ' + name)
    start = match.start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


def sdk_oracle(path):
    if path is None:
        return 'static void sdk_oracle(void) {}\n'
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SDK_SHA:
        raise SystemExit('RTL8277C generated header pin mismatch')
    text = data.decode()
    registers = {
        'EPON_1G': ('EPON_ONU_EPON_RXCTRL', 'RX_EN'),
        'EPON_10G': ('EPON_XGEPN_XMAC_RXMAC_RX_CONFIG', 'mac_en'),
        'GPON': ('GPON_MAC_GPON_onu_ctl', 'en'),
        'XGPON': ('XGPN_XGPN_GLB_CTRL', 'mac_en'),
    }
    output = ''
    for name in [*(r[0] for r in registers.values()), 'PDC_FIFO_STATUS']:
        start = re.search(r'^#define ' + name + r'\s+0x', text, re.M).start()
        end = text.index('#endif /* !__ASSEMBLER__ */', start)
        output += text[start:end] + '#endif\n'
    output += '#define DECL_GATE(name,reg,mask) enum { gate_##name##_reg=reg, gate_##name##_mask=mask };\n'
    output += 'RTL_PON_COLD_RX_GATES(DECL_GATE)\n#undef DECL_GATE\n'
    output += 'static void sdk_oracle(void) {\n'
    for name, (register, field) in registers.items():
        output += f'{{ {register}_t word={{.wrd=~0U}}; word.bf.{field}=0;\n'
        output += f'assert(gate_{name}_reg=={register}-0xf5500000U);\n'
        output += f'assert(word.wrd==~(unsigned)gate_{name}_mask); }}\n'
    output += '''
 PDC_FIFO_STATUS_t fifo={.wrd=~0U}; fifo.bf.depth=0;
 assert(RTL_PON_COLD_PDC_FIFO_STATUS==PDC_FIFO_STATUS-0xf5500000U);
 assert(fifo.wrd==~RTL_PON_COLD_PDC_FIFO_DEPTH);
}
'''
    return output


SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-pon-cold.h"
typedef uint32_t u32;
typedef uint32_t ca_uint32_t;
struct device {int unused;};
struct rtl9617c_pon {void *mac; struct device *ni_dev; void *tx_disable;};
static unsigned regs[0x10000/4],saved[0x10000/4];
static const unsigned offsets[]={0x088c,0x10b4,0x6114,0x4004};
static const unsigned masks[]={1U,1U<<7,1U<<1,3U};
static unsigned writes, gpio_sets, fifo_reads, handoffs, busy_left, polls;
static unsigned stuck_index, stuck_mask;
static bool fifo_stuck;
static int gpio_value, ni_error;
static unsigned offset_of(void *address) {
 ptrdiff_t offset=(unsigned char *)address-(unsigned char *)regs;
 assert(offset>=0 && (unsigned)offset<sizeof(regs) && !(offset&3));
 return (unsigned)offset;
}
static unsigned readl(void *address) {
 unsigned offset=offset_of(address);
 assert(gpio_sets && gpio_value==1);
 if(offset==0x9010) {
  assert(writes>=4);
  for(unsigned i=0;i<4;i++)assert(!(regs[offsets[i]/4]&masks[i]));
  fifo_reads++;
  if(fifo_stuck)return regs[offset/4]|1;
  if(busy_left){busy_left--;return regs[offset/4]|1;}
  return regs[offset/4]&~31U;
 }
 bool known=false;
 for(unsigned i=0;i<4;i++)if(offset==offsets[i])known=true;
 assert(known);return regs[offset/4];
}
static void writel(unsigned value,void *address) {
 unsigned offset=offset_of(address),i;
 assert(gpio_sets && gpio_value==1);
 for(i=0;i<4;i++)if(offset==offsets[i])break;
 assert(i<4);
 /* Only the documented RX fields may change, including reserved bits. */
 assert((value&~masks[i])==(saved[offset/4]&~masks[i]));
 assert(!(value&masks[i]));
 regs[offset/4]=value;
 if(i==stuck_index)regs[offset/4]|=stuck_mask;
 writes++;
}
static void gpiod_set_value_cansleep(void *gpio,int value) {
 (void)gpio;assert(value==1);gpio_sets++;
}
static int gpiod_get_value_cansleep(void *gpio) {(void)gpio;return gpio_value;}
static int rtl9617c_ni_cold_handoff(struct device *dev) {
 (void)dev;assert(gpio_sets && gpio_value==1 && writes>=4 && fifo_reads);
 assert(!fifo_stuck && !busy_left);
 for(unsigned i=0;i<4;i++)assert(!(regs[offsets[i]/4]&masks[i]));
 handoffs++;return ni_error;
}
#define readl_poll_timeout(address,value,condition,delay,timeout) ({ \
 assert((delay)==1 && (timeout)==100000); int poll_result=-ETIMEDOUT; \
 for(unsigned poll_index=0;poll_index<128;poll_index++){ \
  polls++;(value)=readl(address);if(condition){poll_result=0;break;} \
 }poll_result;})
static void setup(unsigned seed) {
 writes=gpio_sets=fifo_reads=handoffs=busy_left=polls=0;
 stuck_index=4;stuck_mask=0;fifo_stuck=false;gpio_value=1;ni_error=0;
 for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i++)regs[i]=i*2654435761U^seed;
 regs[0x9010/4]=0xc000;
 memcpy(saved,regs,sizeof(regs));
}
'''.replace('#include <stdint.h>', '#include <stdint.h>\n#include <stddef.h>')

CASES = r'''
int main(void) {
 struct device ni={};struct rtl9617c_pon pon={.mac=regs,.ni_dev=&ni};
 unsigned cases=0;
 sdk_oracle();
 for(unsigned seed=0;seed<32;seed++)for(unsigned state=0;state<32;state++) {
  setup(1U<<seed);
  for(unsigned i=0;i<4;i++) {
   unsigned field=i==3?((state>>3)&3):((state>>i)&1);
   regs[offsets[i]/4]=(regs[offsets[i]/4]&~masks[i])|
      (field<<(i==0?0:i==1?7:i==2?1:0));
  }
  memcpy(saved,regs,sizeof(regs));busy_left=state%7;
  assert(!rtl_pon_cold_handoff(&pon));
  assert(writes==4 && handoffs==1 && polls==(state%7)+1);
  for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i++) {
   unsigned clear=0;for(unsigned j=0;j<4;j++)if(i==offsets[j]/4)clear=masks[j];
   assert(regs[i]==(saved[i]&~clear));
  }
  /* Retried/deferred probe leaves RX closed and never restores old enables. */
  assert(!rtl_pon_cold_handoff(&pon));assert(writes==8 && handoffs==2);
  cases++;
 }
 for(unsigned i=0;i<4;i++)for(unsigned bit=0;bit<32;bit++)if(masks[i]&(1U<<bit)) {
  setup(0);stuck_index=i;stuck_mask=1U<<bit;
  assert(rtl_pon_cold_handoff(&pon)==-EIO);
  assert(writes==4 && !handoffs && !fifo_reads);
  for(unsigned j=0;j<4;j++)if(j!=i)assert(!(regs[offsets[j]/4]&masks[j]));
 }
 setup(0);gpio_value=0;assert(rtl_pon_cold_handoff(&pon)==-EIO);
 assert(!writes && !handoffs);
 setup(0);gpio_value=-ENODEV;assert(rtl_pon_cold_handoff(&pon)==-ENODEV);
 assert(!writes && !handoffs);
 setup(0);fifo_stuck=true;assert(rtl_pon_cold_handoff(&pon)==-ETIMEDOUT);
 assert(writes==4 && !handoffs && polls==128);
 setup(0);ni_error=-EAGAIN;assert(rtl_pon_cold_handoff(&pon)==-EAGAIN);
 assert(writes==4 && handoffs==1);
 for(unsigned j=0;j<4;j++)assert(!(regs[offsets[j]/4]&masks[j]));
 assert(rtl_pon_cold_rx_gate(NULL)==-EINVAL);
 struct rtl_dq_io bad={};assert(rtl_pon_cold_rx_gate(&bad)==-EINVAL);
 printf("PASS: cold PON RX: %u mode/bit combinations, readback/GPIO/FIFO/NI failures, retry and ordering\n",cases);
 return 0;
}
'''


def change_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Mutation target not unique: ' + repr(old))
    return source.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registers', type=Path)
    args = parser.parse_args()
    text = SOURCE.read_text()
    production = '\n'.join(function(text, name) for name in
                           ('rtl_pon_cold_read', 'rtl_pon_cold_write', 'rtl_pon_cold_handoff'))
    probe = function(text, 'rtl9617c_pon_probe')
    handoff = probe.index('ret = rtl_pon_cold_handoff(pon);')
    assert probe.index('pon->top_irq = devm_platform_ioremap_resource') < handoff
    assert handoff < probe.index('rtl_pon_mpcp_init(')
    # An absent/deferred BOSA must not prevent LAN recovery after a valid
    # receive fence: optical service readiness is not fabric readiness.
    assert handoff < probe.index('"realtek,optical-front-end"')
    assert handoff < probe.index('platform_set_drvdata(pdev, pon)')
    assert handoff < probe.index('rtl_pon_oam_init(') < probe.index('rtl_pon_omci_init(')
    header = HEADER.read_text()
    variants = [
        ('production', header, production),
        ('wrong_gpon_bit', change_once(header, '0x6114U, 1U << 1', '0x6114U, 1U << 2'), production),
        ('partial_xgpon_field', change_once(header, '0x4004U, 3U', '0x4004U, 1U'), production),
        ('reserved_bits_clobbered', change_once(header,
         'io->read(io->context, gates[i].reg) & ~gates[i].mask', '0'), production),
        ('readback_ignored', change_once(header,
         'if (io->read(io->context, gates[i].reg) & gates[i].mask)', 'if (0)'), production),
        ('fifo_timeout_ignored', header, change_once(production,
         'if (ret)\n\t\treturn ret;\n\treturn rtl9617c_ni_cold_handoff',
         'return rtl9617c_ni_cold_handoff')),
    ]
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryDirectory(prefix='pon-cold-') as directory:
        directory = Path(directory)
        compat = directory / 'compat'
        if sys.platform == 'darwin':
            (compat / 'linux').mkdir(parents=True)
            (compat / 'linux/errno.h').write_text('#include <errno.h>\n')
        for name, header_variant, production_variant in variants:
            target = directory / name
            target.mkdir()
            (target / HEADER.name).write_text(header_variant)
            source, binary = target / 'test.c', target / 'test'
            source.write_text(SHIM + sdk_oracle(args.registers) + production_variant + CASES)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                            '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                            '-I', str(target), '-I', str(compat), '-I', str(DRIVER),
                            str(source), '-o', str(binary)], check=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True,
                                    env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1'))
            if name == 'production':
                if result.returncode:
                    raise SystemExit(result.stdout + result.stderr)
                print(result.stdout.strip())
            else:
                assert result.returncode and 'Assertion' in result.stderr, result
                print('PASS: ' + name + ' rejected by runtime assertion')
    print('PASS: probe integration orders cold handoff before IRQ/interface publication')
    if args.registers:
        print('PASS: five register addresses and RX/FIFO fields match pinned RTL8277C unions')


if __name__ == '__main__':
    main()
