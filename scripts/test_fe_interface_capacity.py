#!/usr/bin/env python3
"""Run production EIF ownership against the independent five-bit RTL9617C table."""
import argparse
from pathlib import Path
import hashlib
import json
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
relative = 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--revision', help='Use historical production code with the same physical-table oracle')
args = parser.parse_args()
native = subprocess.check_output(['git', 'show', args.revision + ':' + relative], cwd=root, text=True) if args.revision else (root / relative).read_text()
def function(name):
    found = re.search(r'^static int ' + name + r'\(', native, re.M)
    if not found:
        return ''
    start = found.start()
    end = native.index('{', start) + 1
    depth = 1
    while depth:
        depth += (native[end] == '{') - (native[end] == '}')
        end += 1
    return native[start:end]

constants = '\n'.join(re.findall(r'^#define FE_(?:INTERFACES|COUNTERS) \d+', native, re.M))
interface = re.search(r'struct rtl_fe_interface \{.*?\n\};', native, re.S).group()
common = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BIT(n) (1U<<(n))
/* Independent SDK hardware constraints, ca-network-drivers commit
 * 8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0:
 * registers.h L3FE_GLB_EGRESS_L3_IF_TBL_ACCESS_t has addr:5, reserved:25;
 * aal-77c/include/aal_l3_if.h FE_L3E_IF_TBL_ENTRY_MAX is32 (2^5).
 * Six-bit action selectors cannot create extra physical storage. */
union sdk_access {unsigned int word;struct {unsigned int addr:5,reserved:25,write:1,busy:1;} bits;};
union sdk_eif {unsigned int word;struct {unsigned int pppoe_set:1,pppoe_vld:1,pppoe_session_id:16,mac_sa_vld:1,mac_sa_an_sel:4,pppoe_len_control:1,reserved:8;} fields;};
_Static_assert(sizeof(union sdk_access)==4,"SDK five-bit access row");
_Static_assert(sizeof(union sdk_eif)==4,"SDK EIF row width");
struct rtl_fe_flow {unsigned int source_mac,counter,pppoe;bool counted,interface_owned;};
struct rtl_fe {unsigned long counters[1];struct rtl_fe_interface interfaces[FE_INTERFACES];
 unsigned int table[32],data,window_writes,requests,polls,busy_at;bool busy,fail_read,fail_write;
 unsigned char registers[0x4000];};
static struct rtl_fe *active;
static unsigned int find_first_zero_bit(unsigned long *bits,unsigned int size){for(unsigned int i=0;i<size;i++)if(!(bits[i/64]&(1UL<<(i%64))))return i;return size;}
static void __set_bit(unsigned int i,unsigned long *b){b[i/64]|=1UL<<(i%64);}
static void __clear_bit(unsigned int i,unsigned long *b){b[i/64]&=~(1UL<<(i%64));}
static unsigned int fe_read(struct rtl_fe *fe,unsigned int reg){assert(reg==0x3004);return fe->data;}
static void fe_write(struct rtl_fe *fe,unsigned int reg,unsigned int value){assert(reg==0x3004);assert(!fe->busy);fe->data=value;fe->window_writes++;}
static int fe_access(struct rtl_fe *fe,unsigned int reg,unsigned int value){
 assert(reg==0x3000);union sdk_access command={.word=value};unsigned int index=command.bits.addr;
 fe->requests++;
 if(command.bits.write) {
  /* Completion timeout is ambiguous: hardware may already have programmed it. */
  fe->table[index]=fe->data;
  if(fe->fail_write){fe->fail_write=false;fe->busy=true;return -ETIMEDOUT;}
 } else {
  if(fe->fail_read){fe->fail_read=false;fe->busy=true;return -ETIMEDOUT;}
  fe->data=fe->table[index];
 }
 return 0;
}
static int idle(void *address,unsigned int timeout){
 assert(address==active->registers+0x3000 && timeout==100000);active->polls++;
 return active->busy || active->polls==active->busy_at?-ETIMEDOUT:0;
}
#define readl_poll_timeout(address,value,condition,delay,timeout) ((void)(value=0),idle(address,timeout))
static void init(struct rtl_fe *fe){memset(fe,0,sizeof(*fe));active=fe;for(unsigned int i=0;i<32;i++)fe->table[i]=0x50000000+i;}
static unsigned int recipe(const struct rtl_fe_flow *f){return BIT(23)|BIT(18)|((f->source_mac+1)<<19)|f->pppoe;}
static void capacity_counterexample(void){
 struct rtl_fe fe;init(&fe);struct rtl_fe_flow flows[33]={0};
 for(unsigned int i=0;i<32;i++){flows[i].source_mac=i%15;flows[i].pppoe=3U|((i+100U)<<2);assert(!fe_interface_get(&fe,&flows[i]));}
 unsigned int row0=fe.table[0];flows[32]=(struct rtl_fe_flow){.source_mac=14,.pppoe=3U|(900U<<2)};
 int ret=fe_interface_get(&fe,&flows[32]);
 /* First assertion detects the actual historical32->0 live recipe overwrite,
  * not a hardcoded expected software capacity or a missing new helper. */
 assert(fe.table[0]==row0 && "33rd allocation must not overwrite physical row0");
 assert(ret==-ENOSPC && !flows[32].interface_owned);
 for(unsigned int i=0;i<32;i++)assert(fe.table[flows[i].counter]==recipe(&flows[i]));
 for(unsigned int i=0;i<32;i++)assert(!fe_interface_put(&fe,&flows[i]));
}
static void shared_lifetime(void){
 struct rtl_fe fe;init(&fe);struct rtl_fe_flow *flows=calloc(4096,sizeof(*flows));assert(flows);
 for(unsigned int i=0;i<4096;i++) {
  flows[i].source_mac=i%15;flows[i].pppoe=3U|((i%2?1234U:3456U)<<2);
  assert(!fe_interface_get(&fe,&flows[i]));assert(flows[i].counter<32);
  assert(fe.table[flows[i].counter]==recipe(&flows[i]));assert(flows[i].counted==(i<32));
  union sdk_eif row={.word=fe.table[flows[i].counter]};assert(row.fields.pppoe_len_control && row.fields.pppoe_set && row.fields.pppoe_vld && row.fields.mac_sa_vld && !row.fields.reserved);
  assert(row.fields.pppoe_session_id==(i%2?1234U:3456U) && row.fields.mac_sa_an_sel==i%15+1);
 }
 for(unsigned int i=0;i<32;i++)assert(!fe_interface_put(&fe,&flows[i]));
 struct rtl_fe_flow replacement={.source_mac=0,.pppoe=3U|(3456U<<2)};
 assert(!fe_interface_get(&fe,&replacement) && replacement.counted);assert(!fe_interface_put(&fe,&replacement));
 for(unsigned int i=32;i<4096;i++)assert(!fe_interface_put(&fe,&flows[i]));
 assert(!fe.counters[0]);for(unsigned int i=0;i<32;i++)assert(!fe.interfaces[i].users && fe.table[i]==0x50000000+i);
 /* Retain the original non-PUSH PPPoE REMOVE/KEEP padding policy cases. */
 for(unsigned int pppoe=0;pppoe<=1;pppoe++) {
  struct rtl_fe_flow plain={.source_mac=14,.pppoe=pppoe};
  assert(!fe_interface_get(&fe,&plain));union sdk_eif row={.word=fe.table[plain.counter]};
  assert(row.fields.pppoe_set==pppoe && !row.fields.pppoe_vld && !row.fields.pppoe_session_id);
  assert(row.fields.pppoe_len_control && row.fields.mac_sa_vld && row.fields.mac_sa_an_sel==15);
  assert(!fe_interface_put(&fe,&plain) && fe.table[0]==0x50000000);
 }
 free(flows);
}
static void failure_ownership(void){
 struct rtl_fe fe;struct rtl_fe_flow failed={.source_mac=3,.pppoe=3U|(7U<<2)};init(&fe);
 unsigned int invalid=0xabc;assert(fe_interface_transfer(&fe,32,&invalid,true)==-ERANGE && !fe.requests && !fe.window_writes && !fe.polls);
 fe.busy=true;fe.data=0xaabbccdd;
 assert(fe_interface_get(&fe,&failed)==-ETIMEDOUT && !failed.interface_owned && !fe.requests && !fe.window_writes && fe.data==0xaabbccdd);
 fe.busy=false;fe.fail_read=true;
 assert(fe_interface_get(&fe,&failed)==-ETIMEDOUT && !failed.interface_owned && !fe.counters[0]);
 fe.busy=false;fe.busy_at=fe.polls+2;unsigned int before=fe.window_writes;
 assert(fe_interface_get(&fe,&failed)==-ETIMEDOUT && failed.interface_owned && !fe.interfaces[0].ready && fe.window_writes==before);
 fe.busy_at=0;assert(!fe_interface_put(&fe,&failed) && !fe.counters[0]);failed=(struct rtl_fe_flow){.source_mac=3,.pppoe=3U|(7U<<2)};
 fe.fail_write=true;
 assert(fe_interface_get(&fe,&failed)==-ETIMEDOUT && failed.interface_owned && !fe.interfaces[0].ready && fe.interfaces[0].users==1);
 /* Simulate delayed completion: the reserved recipe remains unready even
  * after BUSY clears. Fill all other rows and reject sharing that recipe. */
 fe.busy=false;struct rtl_fe_flow rest[31]={0};
 for(unsigned int i=0;i<31;i++){rest[i].source_mac=1;rest[i].pppoe=3U|((100U+i)<<2);assert(!fe_interface_get(&fe,&rest[i]));}
 struct rtl_fe_flow same={.source_mac=3,.pppoe=3U|(7U<<2)};
 assert(fe_interface_get(&fe,&same)==-ENOSPC && !same.interface_owned && fe.interfaces[0].users==1);
 fe.busy=true;before=fe.window_writes;
 assert(fe_interface_put(&fe,&failed)==-ETIMEDOUT && fe.window_writes==before && fe.interfaces[0].users==1 && fe.counters[0]&1UL);
 fe.busy=false;fe.fail_write=true;
 assert(fe_interface_put(&fe,&failed)==-ETIMEDOUT && !fe.interfaces[0].ready && fe.interfaces[0].users==1 && fe.counters[0]&1UL);
 fe.busy=false;assert(fe_interface_get(&fe,&same)==-ENOSPC && !same.interface_owned);
 assert(!fe_interface_put(&fe,&failed) && !fe.interfaces[0].users && !(fe.counters[0]&1UL));assert(fe.table[0]==0x50000000);
 /* Also start from a confirmed-ready row: a failed last-owner restore
  * must revoke sharing eligibility, not just retain the occupancy bit. */
 struct rtl_fe_flow filler={.source_mac=14,.pppoe=3U|(999U<<2)};
 assert(!fe_interface_get(&fe,&filler));assert(fe.interfaces[rest[0].counter].ready);
 fe.fail_write=true;
 assert(fe_interface_put(&fe,&rest[0])==-ETIMEDOUT && !fe.interfaces[rest[0].counter].ready);
 fe.busy=false;struct rtl_fe_flow during_restore={.source_mac=1,.pppoe=3U|(100U<<2)};
 assert(fe_interface_get(&fe,&during_restore)==-ENOSPC && !during_restore.interface_owned);
 assert(!fe_interface_put(&fe,&rest[0]));assert(!fe_interface_put(&fe,&filler));
 for(unsigned int i=1;i<31;i++)assert(!fe_interface_put(&fe,&rest[i]));
 assert(!fe.counters[0]);
}
int main(void){
 capacity_counterexample();shared_lifetime();failure_ownership();
 puts("Native EIF: physical32-row/five-bit alias oracle;4096 flows/30 recipes;33 distinct recipes reject;busy/ambiguous write/unready sharing/restore retry passed");
}
'''
# Compile historical functions unchanged: old negative control reaches the
# physical alias oracle before any new readiness-specific cases.
prefix = common[:common.index('static void capacity_counterexample')]
tests = common[common.index('static void capacity_counterexample'):]
if not re.search(r'\bready\b', interface):
    tests = tests[:tests.index('static void failure_ownership')]
    tests += '\nint main(void){capacity_counterexample();shared_lifetime();return 0;}\n'
parts = ['#include <stdbool.h>', constants, interface, prefix]
parts += [function(n) for n in ('fe_interface_transfer', 'fe_interface_get', 'fe_interface_put')]
parts += [tests]
(root / 'artifacts').mkdir(exist_ok=True)
(root / 'logs').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=root / 'artifacts', prefix='fe-interface-') as work:
    path = Path(work) / 'interfaces.c'
    binary = Path(work) / 'interfaces'
    path.write_text('\n'.join(parts))
    subprocess.run(['cc', '-std=c11', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
(root / 'logs/fe-interface-capacity.json').write_text(json.dumps({
    'production_source_sha256': hashlib.sha256(native.encode()).hexdigest(),
    'flows': 4096, 'recipes': 30, 'physical_forwarding_interfaces': 32,
    'hardware_access_address_bits': 5, 'thirty_third_recipe_preserves_live_row_zero': True,
    'busy_before_data_window_and_ambiguous_programming_retry': True,
    'unready_row_not_shared': True, 'last_owner_restore_retry': True,
    'sanitizers': ['ASan', 'UBSan'], 'hardware_verified': False,
}, indent=2) + '\n')
