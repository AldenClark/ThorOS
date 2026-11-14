#!/usr/bin/env python3
"""Execute pinned Linux forwarding/VLAN code against Ethernet frame budgets.

This is an independent Linux contract oracle, not an ASIC model. Frame sizes
include a modeled four-byte wire FCS; Linux skb lengths exclude it. No claim is
made about a chip register's counting convention, actual forwarding or drain.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel', required=True, type=Path, help='Same prepared pinned kernel used by object checks')
args = parser.parse_args()
kernel = args.kernel.resolve()
lock = json.loads((root / 'port/sources.lock.json').read_text())['openwrt']
makefile = (kernel / 'Makefile').read_text()
version = '.'.join(re.search(r'^' + key + r'\s*=\s*(\d+)$', makefile, re.M)[1]
                   for key in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL'))
assert version == lock['kernel'], (version, lock['kernel'])
paths = ('include/linux/netdevice.h', 'include/linux/if_vlan.h', 'include/uapi/linux/if_ether.h',
         'net/core/dev.c', 'net/core/skbuff.c', 'net/8021q/vlan_netlink.c', 'net/bridge/br_forward.c')
sources = {path: (kernel / path).read_text() for path in paths}


def function(text, name):
    match = re.search(r'(?m)^(?:static\s+)?(?:(?:inline|__always_inline)\s+)?[\w *]+\b' +
                      name + r'\([^;{}]*\)\s*\{', text)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]


def constant(path, name):
    return int(re.search(r'^#define\s+' + name + r'\s+(\d+)\b', sources[path], re.M)[1])


constants = {name: constant('include/uapi/linux/if_ether.h', name)
             for name in ('ETH_HLEN', 'ETH_DATA_LEN', 'ETH_FCS_LEN')}
constants['VLAN_HLEN'] = constant('include/linux/if_vlan.h', 'VLAN_HLEN')
netdevice = sources['include/linux/netdevice.h']
forwardable = function(netdevice, '__is_skb_forwardable')
reduce_mtu = function(netdevice, 'netif_reduces_vlan_mtu')
untag = function(sources['net/core/skbuff.c'], 'skb_vlan_untag')
bridge = function(sources['net/bridge/br_forward.c'], 'br_dev_queue_push_xmit')
wrapper = function(sources['net/core/dev.c'], 'is_skb_forwardable')
# Execute the exact VLAN creation MTU calculation/validation, without modeling
# unrelated netlink registration. Its lower device can itself be a VLAN device.
newlink = function(sources['net/8021q/vlan_netlink.c'], 'vlan_newlink')
mtu = newlink[newlink.index('\tmax_mtu = netif_reduces_vlan_mtu('):newlink.index('\n\t/* Note: If this initial')]
assert 'return netif_is_macsec(dev);' in reduce_mtu
rx = function(sources['net/core/dev.c'], '__netif_receive_skb_core')
assert rx.index('skb = skb_vlan_untag(skb);') < rx.index('rx_handler = rcu_dereference(skb->dev->rx_handler);')
assert untag.index('__vlan_hwaccel_put_tag(') < untag.index('skb_pull_rcsum(skb, VLAN_HLEN)')
assert bridge.index('skb_push(skb, ETH_HLEN)') < bridge.index('is_skb_forwardable(')

common = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
typedef uint32_t u32;
typedef uint16_t u16;
#define __always_inline inline
#define IFF_UP 1
#define unlikely(x) (x)
#define GFP_ATOMIC 0
#define CHECKSUM_PARTIAL 1
#define IFLA_MTU 0
struct net_device {unsigned flags,mtu,hard_header_len;bool macsec;};
struct sk_buff {
 unsigned len,protocol,ip_summed;bool gso,tag_present,freed,queued;
 unsigned char *data;struct net_device *dev;
};
struct vlan_hdr {u16 h_vlan_TCI,h_vlan_encapsulated_proto;};
struct net {int unused;};
struct sock {int unused;};
static bool netif_is_macsec(struct net_device *dev){return dev->macsec;}
static bool skb_is_gso(const struct sk_buff *skb){return skb->gso;}
static bool skb_vlan_tag_present(const struct sk_buff *skb){return skb->tag_present;}
static struct sk_buff *skb_share_check(struct sk_buff *skb,int flags){(void)flags;return skb;}
static bool pskb_may_pull(struct sk_buff *skb,unsigned length){return skb->len>=length;}
static void __vlan_hwaccel_put_tag(struct sk_buff *skb,unsigned protocol,u16 tci){
 (void)protocol;(void)tci;skb->tag_present=true;
}
static void skb_pull_rcsum(struct sk_buff *skb,unsigned length){assert(skb->len>=length);skb->len-=length;skb->data+=length;}
static void vlan_set_encap_proto(struct sk_buff *skb,struct vlan_hdr *vhdr){skb->protocol=vhdr->h_vlan_encapsulated_proto;}
static struct sk_buff *skb_reorder_vlan_header(struct sk_buff *skb){return skb;}
static void skb_reset_network_header(struct sk_buff *skb){(void)skb;}
static bool skb_transport_header_was_set(struct sk_buff *skb){(void)skb;return true;}
static void skb_reset_transport_header(struct sk_buff *skb){(void)skb;}
static void skb_reset_mac_len(struct sk_buff *skb){(void)skb;}
static void kfree_skb(struct sk_buff *skb){skb->freed=true;}
static void skb_push(struct sk_buff *skb,unsigned length){skb->len+=length;}
static void br_drop_fake_rtable(struct sk_buff *skb){(void)skb;}
static bool eth_type_vlan(unsigned protocol){return protocol==0x8100||protocol==0x88a8;}
static bool vlan_get_protocol_and_depth(struct sk_buff *skb,unsigned protocol,int *depth){(void)skb;(void)protocol;*depth=0;return true;}
static void skb_set_network_header(struct sk_buff *skb,int depth){(void)skb;(void)depth;}
static void br_switchdev_frame_set_offload_fwd_mark(struct sk_buff *skb){(void)skb;}
static void dev_queue_xmit(struct sk_buff *skb){skb->queued=true;}
'''
# Kernel header may define __always_inline through libc's feature headers.
common = common.replace('#define __always_inline inline', '#undef __always_inline\n#define __always_inline inline')
unit = common + '\n' + '\n'.join('#define ' + key + ' ' + str(value) for key, value in constants.items())
unit += '\n' + reduce_mtu + '\n' + forwardable + '\n' + wrapper + '\n' + untag + '\n' + bridge
unit += '''
static int inherited_vlan_mtu(struct net_device *dev,struct net_device *real_dev,bool explicit_mtu) {
 void *tb[1]={explicit_mtu?(void *)1:NULL};unsigned max_mtu;
''' + mtu + '\n return 0;\n}\n'
unit += r'''
/* A receive capacity expressed in wire-byte units is a policy fixture here.
 * This test does not interpret any RTL9617C register field. */
#define PRESERVED_RECEIVE_WIRE_BUDGET 9201
int main(void){
 struct net_device physical={.flags=IFF_UP,.mtu=ETH_DATA_LEN,.hard_header_len=ETH_HLEN};
 struct net_device vlan1=physical,vlan2=physical;
 assert(!inherited_vlan_mtu(&vlan1,&physical,false));
 assert(!inherited_vlan_mtu(&vlan2,&vlan1,false));
 assert(vlan1.mtu==1500 && vlan2.mtu==1500); /* stacking does not subtract 8 */
 struct net_device macsec=physical,macsec_vlan=physical;macsec.macsec=true;
 assert(!inherited_vlan_mtu(&macsec_vlan,&macsec,false) && macsec_vlan.mtu==1496);
 vlan1.mtu=1501;assert(inherited_vlan_mtu(&vlan1,&physical,true)==-EINVAL);
 vlan1.mtu=1500;assert(!inherited_vlan_mtu(&vlan1,&physical,true));
 const unsigned expected_wire[]={1518,1522,1526};
 const unsigned expected_skb[]={1514,1514,1518};
 for(unsigned tags=0;tags<=2;tags++){
  unsigned wire=ETH_HLEN+ETH_DATA_LEN+tags*VLAN_HLEN+ETH_FCS_LEN;
  assert(wire==expected_wire[tags]);
  unsigned char data[16]={0};
  struct sk_buff skb={.len=wire-ETH_FCS_LEN-ETH_HLEN,.data=data,.dev=&physical};
  /* For this bridge case the outer VLAN becomes skb metadata before the
   * bridge handler. FCS was never part of skb data. Use the kernel's real
   * untag helper, then its bridge egress helper (which restores ETH_HLEN). */
  if(tags){assert(skb_vlan_untag(&skb)==&skb);assert(skb.tag_present);}
  assert(!br_dev_queue_push_xmit(NULL,NULL,&skb));
  assert(skb.len==expected_skb[tags] && skb.queued && !skb.freed);
  assert(__is_skb_forwardable(&physical,&skb,true));
  /* A global fixed 1522-byte wire ceiling rejects the legal QinQ case,
   * before the CPU fallback can perform the normalization above. */
  assert(wire<=PRESERVED_RECEIVE_WIRE_BUDGET);
  assert((wire<=1522)==(tags<2));
 }
 struct sk_buff edge={.len=1518};assert(__is_skb_forwardable(&physical,&edge,true));
 edge.len=1519;assert(!__is_skb_forwardable(&physical,&edge,true));
 edge.gso=true;assert(__is_skb_forwardable(&physical,&edge,true));
 edge.gso=false;assert(__is_skb_forwardable(&physical,&edge,false));
 physical.flags=0;assert(!__is_skb_forwardable(&physical,&edge,false));
 puts("Pinned Linux frame contract: VLAN/QinQ inherit 1500 MTU; wire 1518/1522/1526 -> bridge skb 1514/1514/1518 accepted; fixed 1522 counterexample verified");
}
'''
with tempfile.TemporaryDirectory(prefix='fabric-frame-contract-') as temporary:
    temporary = Path(temporary)
    for name, text, passed in (
        ('linux_contract', unit, True),
        ('wrong_global_1522', unit.replace('#define PRESERVED_RECEIVE_WIRE_BUDGET 9201',
                                          '#define PRESERVED_RECEIVE_WIRE_BUDGET 1522'), False),
    ):
        cfile,binary=temporary/(name+'.c'),temporary/name
        cfile.write_text(text)
        subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                        '-O1','-g','-fsanitize=address,undefined',str(cfile),'-o',str(binary)],check=True)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
        if passed:
            assert result.returncode==0,result.stdout+result.stderr
            print(result.stdout,end='')
        else:
            assert result.returncode!=0 and 'Assertion' in result.stderr and 'PRESERVED_RECEIVE_WIRE_BUDGET' in result.stderr,result.stderr
            print('wrong_global_1522: rejected by QinQ wire-budget runtime assertion')
print('Evidence scope: Linux forwarding/MTU contract and modeled wire budget only; hardware_forwarding_proven=false')
evidence = {
    'schema': 1, 'kernel': version, 'openwrt_commit': lock['commit'],
    'sources_sha256': {path: hashlib.sha256((kernel/path).read_bytes()).hexdigest() for path in paths},
    'executed_functions': ['__is_skb_forwardable','is_skb_forwardable','netif_reduces_vlan_mtu',
                           'skb_vlan_untag','br_dev_queue_push_xmit'],
    'executed_snippets': ['vlan_newlink MTU calculation and explicit-MTU validation'],
    'wire_bytes_including_modeled_fcs': [1518,1522,1526],
    'bridge_skb_bytes_after_outer_tag_metadata': [1514,1514,1518],
    'wrong_1522_negative_control_rejected': True,
    'hardware_register_counting_semantics_proven': False,
    'hardware_forwarding_proven': False,
}
(root/'artifacts').mkdir(exist_ok=True)
(root/'artifacts/fabric-frame-contract.json').write_text(json.dumps(evidence,indent=2)+'\n')
