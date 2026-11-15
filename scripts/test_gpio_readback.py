#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise extracted GPIO getters against independent bank/register vectors.

Optional --sdk compiles the actual pinned Cortina getter for comparison.
Host MMIO model only; it does not prove any physical pad state or boot cause.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/gpio/gpio-rtl9617c.c'
SDK_SHA = '126dec4a70a8918d2199defa503ca6c54fbb29bf69de597e5c8d0c3d3ed069aa'
# https://github.com/jameywine/GPL-for-GP3000/blob/
# 5090fbcb6ba743dd7b1314811ef557bad0460147/linux-5.10.x/drivers/gpio/gpio-ca77xx.c


def function(source, name):
    match = re.search(r'^static [^\n]*\b' + re.escape(name) + r'\(', source, re.M)
    if not match:
        raise ValueError('Missing function ' + name)
    start = match.start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


SHIM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define __iomem
#define BIT(n) (1U << (n))
#define GPIO_LINE_DIRECTION_IN 1
#define GPIO_LINE_DIRECTION_OUT 0
#define GPIOF_DIR_IN 1
#define GPIOF_DIR_OUT 0
typedef uint32_t u32;
struct gpio_chip { void *data; };
struct rtl_gpio { void *base; int lock; struct gpio_chip chip; };
struct ca77xx_gpio_bank { void *reg; int lock; };
#define gpiochip_get_data(chip) ((chip)->data)
static unsigned held,reads,acquires;
#define spin_lock_irqsave(lock,flags) do { (void)(lock); (flags)=0; assert(!held); held=1; acquires++; } while (0)
#define spin_unlock_irqrestore(lock,flags) do { (void)(lock); (void)(flags); assert(held); held=0; } while (0)
#define raw_spin_lock_irqsave spin_lock_irqsave
#define raw_spin_unlock_irqrestore spin_unlock_irqrestore
static u32 readl(void *address) { assert(held); reads++; return *(u32 *)address; }
#define ioread32 readl
static u32 regs[5*9];
'''
MAIN = r'''
int main(void) {
 struct rtl_gpio gpio={.base=regs}; struct gpio_chip chip={.data=&gpio};
 unsigned cases=0;
 for (unsigned pin=0;pin<160;pin++)
  for(unsigned input=0;input<2;input++)
   for(unsigned out=0;out<2;out++)
    for(unsigned in=0;in<2;in++)
     for(unsigned noise=0;noise<2;noise++) {
      /* Independent register oracle: bank stride36, CFG0, OUT4, IN8. */
      for(unsigned i=0;i<45;i++) regs[i]=noise ? ~0U : 0;
      unsigned bank=pin/32,mask=1U<<(pin%32),index=bank*9;
      regs[index]=(regs[index]&~mask)|(input ? mask : 0);
      regs[index+1]=(regs[index+1]&~mask)|(out ? mask : 0);
      regs[index+2]=(regs[index+2]&~mask)|(in ? mask : 0);
      u32 saved[45]; memcpy(saved,regs,sizeof(regs));
      reads=0; acquires=0;
      assert(rtl_gpio_direction(&chip,pin)==(int)input);
      assert(!held && reads==1 && acquires==1);
      reads=0; acquires=0;
      int actual=rtl_gpio_get(&chip,pin);
      assert(actual==(int)(input ? in : out));
      assert(!held && reads==2 && acquires==1);
      sdk_compare(bank,pin%32,actual);
      assert(!held && !memcmp(saved,regs,sizeof(regs)));
      cases++;
     }
 printf("PASS GPIO readback: %u vectors, all 160 pins/five banks; direction+data locked; no MMIO writes\n",cases);
 return 0;
}
'''


def sdk_oracle(path):
    if path is None:
        return 'static void sdk_compare(unsigned b,unsigned p,int v) {(void)b;(void)p;(void)v;}\n'
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SDK_SHA:
        raise SystemExit('Cortina GPIO source pin mismatch')
    sdk = data.decode()
    result = ''
    for macro in ('CA77XX_GPIO_CFG', 'CA77XX_GPIO_OUT', 'CA77XX_GPIO_IN', 'CA77XX_GPIO_CFG_IN'):
        result += re.search(r'^#define ' + macro + r'\s+[^\n]+', sdk, re.M).group() + '\n'
    result += '\n'.join(function(sdk, name) for name in (
        'ca77xx_gpio_read', '_ca77xx_gpio_get_bit',
        'ca77xx_gpio_get_direction', 'ca77xx_gpio_get'))
    return result + r'''
static void sdk_compare(unsigned bank,unsigned pin,int expected) {
 struct ca77xx_gpio_bank state={.reg=&regs[bank*9]};
 struct gpio_chip chip={.data=&state};
 assert(ca77xx_gpio_get(&chip,pin)==expected);
}
'''


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path)
    args = parser.parse_args()
    source = SOURCE.read_text()
    unit = '\n'.join(function(source, name) for name in (
        'rtl_gpio_reg', 'rtl_gpio_direction_locked', 'rtl_gpio_get', 'rtl_gpio_direction'))
    old = function(source, 'rtl_gpio_get')
    # Keep the new lock intact: the legacy always-IN semantic must fail vectors.
    mutant = old.replace('rtl_gpio_reg(gpio, pin, reg)', 'rtl_gpio_reg(gpio, pin, 8)')
    assert mutant != old
    with tempfile.TemporaryDirectory(prefix='gpio-readback-') as tmp:
        tmp = Path(tmp)
        for label, body, success in (
            ('production', unit, True),
            ('legacy_always_input', unit.replace(old, mutant), False),
        ):
            cfile = tmp / (label + '.c')
            cfile.write_text(SHIM + body + sdk_oracle(args.sdk) + MAIN)
            binary = tmp / label
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra',
                            str(cfile), '-o', str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, preexec_fn=no_core)
            assert (result.returncode == 0) == success, (label, result.stdout, result.stderr)
            if success:
                print(result.stdout.strip())
            else:
                print('PASS negative control: old always-IN getter rejected')
    print('SDK actual getter comparison: ' + ('PASS (pinned source)' if args.sdk else 'not requested'))
    print('Host register model only; physical GPIO state and boot root cause unproven.')


if __name__ == '__main__':
    main()
