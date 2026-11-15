#!/usr/bin/env python3
"""Run native GPON probe/NI DMA completion across down-netdev destruction.

This compiles the production GPON drain probe, OMCI ndo_stop/remove, OAM free,
NI close/transmit/forget, and DMA publish/complete functions unchanged. MMIO
and kernel scheduling are host fixtures; no hardware drain is inferred.
"""
import argparse
import ast
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
driver = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mutants', action='store_true')
args = parser.parse_args()
sources = {name: (driver / ('rtl9617c-' + name + '.c')).read_text()
           for name in ('dma', 'xram', 'pon-omci', 'pon-oam', 'pon-gpon')}


def function(source, name):
    match = re.search(r'(?m)^(?:static\s+)?[\w *]+\b' + name +
                      r'\([^;{}]*\)\s*\{', source)
    assert match, name
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


# Reuse the existing DMA fixture, not its alternative implementation of TX.
tree = ast.parse((root / 'scripts/test_dma_tx_fastpath.py').read_text())
constants = {node.targets[0].id: ast.literal_eval(node.value)
             for node in tree.body if isinstance(node, ast.Assign) and
             isinstance(node.targets[0], ast.Name) and node.targets[0].id in ('model', 'available')}
fixture = constants['model'].replace(
    'struct net_device {bool stopped;',
    'struct net_device {void *priv;bool stopped,running,registered;')
fixture = fixture.replace(
    'struct sk_buff {const u8 *data;unsigned len;bool freed,failed;};',
    'struct sk_buff {u8 *data;unsigned len;bool freed,failed,dynamic;};')
fixture = fixture.replace(
    'static void dev_kfree_skb_any(struct sk_buff *s){assert(!s->freed);s->freed=true;}',
    'static void dev_kfree_skb_any(struct sk_buff *s){assert(!s->freed);s->freed=true;'
    'if(s->dynamic){free(s->data);free(s);}}')
fixture += constants['available'] + r'''
#include <errno.h>
#define GFP_KERNEL 0
#define spin_lock_irqsave(p,f) do { (f)=0;assert(!*(p));*(p)=1;lock_count++; } while(0)
#define spin_unlock_irqrestore(p,f) do { (void)(f);assert(*(p));*(p)=0; } while(0)
struct device {struct net_device *data;};
struct rtl_xram {
 struct rtl_dma_tx dma;int tx_lock;void *fe;
 bool host_active,removing,engine_poisoned;unsigned engine_users;
};
struct rtl_gpon_drain {unsigned port,probe;};
struct rtl9617c_pon {
 struct device *ni_dev;struct net_device *omci_device;
 void *omci_cmac,*omci_kdf;int lock;
 struct rtl_gpon_drain gpon_drain;
};
struct rtl_oam_port {struct rtl9617c_pon *pon;unsigned llid;bool control;};
static unsigned lock_count,engine_puts,forget_checks,netdev_frees,ni_kicks,fe_removes;
static struct rtl_xram *active;
static struct rtl9617c_pon *active_pon;
static void *netdev_priv(struct net_device *d){return d->priv;}
static struct net_device *dev_get_drvdata(struct device *d){return d->data;}
static void mutex_lock(int *p){assert(!*p);*p=1;}
static void mutex_unlock(int *p){assert(*p);*p=0;}
static void rtl_fe_flush_port(void *fe,struct net_device *owner){(void)fe;assert(owner);}
static void rtl_engine_put(struct rtl_xram *p) {
 assert(p==active && p->engine_users>1);p->engine_users--;engine_puts++;
}
static void rtl_tx_timer_kick_locked(struct rtl_xram *p){assert(p->tx_lock);ni_kicks++;}
static struct sk_buff *alloc_skb(unsigned n,int flags) {
 assert(n==64 && !flags);struct sk_buff *s=calloc(1,sizeof(*s));assert(s);
 s->data=malloc(n);assert(s->data);s->dynamic=true;return s;
}
static void *skb_put(struct sk_buff *s,unsigned n){void *p=s->data+s->len;s->len+=n;assert(s->len<=64);return p;}
static void rtl_pon_dying_gasp_stop(struct rtl9617c_pon *p){assert(p==active_pon);}
static int rtl_omci_stop(struct net_device *dev);
static void unregister_netdev(struct net_device *d) {
 assert(d->registered);d->registered=false;
 if(d->running){d->running=false;assert(!rtl_omci_stop(d));}
}
static void free_netdev(struct net_device *d){assert(!d->registered && !d->running);netdev_frees++;free(d);}
static void crypto_free_shash(void *p){assert(!p);}
static void rtl9617c_ni_fe_remove_port(struct device *ni,struct net_device *d) {
 assert(ni==active_pon->ni_dev && d);fe_removes++;
}
'''

functions = ''.join(function(sources['dma'], name) for name in
                    ('rtl_dma_vp', 'rtl_dma_tx_complete', 'rtl_dma_tx_forget', 'rtl_dma_tx_frame'))
functions += ''.join(function(sources['xram'], name) for name in
                     ('rtl9617c_ni_close', 'rtl9617c_ni_forget_tx', 'rtl9617c_ni_transmit'))
functions += function(sources['pon-omci'], 'rtl_omci_stop')
functions += function(sources['pon-gpon'], 'rtl_gpon_drain_probe')
destructors = (function(sources['pon-omci'], 'rtl_pon_omci_remove') +
               function(sources['pon-oam'], 'rtl_oam_free'))

tests = r'''
static void submit_lan(struct rtl_xram *ni,struct net_device *lan) {
 u8 bytes[64]={};struct sk_buff s={.data=bytes,.len=64};
 unsigned long flags;spin_lock_irqsave(&ni->tx_lock,flags);
 assert(rtl_dma_tx_frame(&ni->dma,&s,lan,NULL)==NETDEV_TX_OK && s.freed);
 spin_unlock_irqrestore(&ni->tx_lock,flags);
}
static void complete(struct rtl_xram *ni,struct net_device *lan) {
 unsigned long flags;spin_lock_irqsave(&ni->tx_lock,flags);
 writel(ni->dma.write,rtl_dma_vp(&ni->dma)+VP_READ);
 rtl_dma_tx_complete(&ni->dma,lan);spin_unlock_irqrestore(&ni->tx_lock,flags);
}
int main(void) {
 for(unsigned role=0;role<3;role++) {
  struct rtl_xram ni={.host_active=true,.engine_users=2};
  struct net_device lan={.priv=&ni,.running=true,.registered=true};
  struct device parent={.data=&lan};
  struct rtl9617c_pon pon={.ni_dev=&parent};
  struct rtl9617c_pon *pon_ptr=&pon;
  struct rtl_oam_port port={.pon=&pon,.control=role==1};
  struct net_device *owner=calloc(1,sizeof(*owner));assert(owner);
  owner->priv=role?(void *)&port:(void *)&pon_ptr;
  owner->registered=owner->running=true;pon.omci_device=owner;
  active=&ni;active_pon=&pon;lock_count=engine_puts=netdev_frees=ni_kicks=fe_removes=0;
  ni.dma.memory_dma=0x04000000;ni.dma.port=0;ni.dma.vp=8;
  ni.dma.memory=calloc(1,MEMORY_BYTES);ni.dma.registers=calloc(1,4096);
  assert(ni.dma.memory && ni.dma.registers);ni.dma.descriptors=ni.dma.memory;
  if(!role) {
   /* OMCI was up to activate GPON, then userspace took only OMCI down.
    * ndo_stop forgets existing descriptors but does not stop the GPON
    * recovery worker. LAN keeps the shared NI owner active. */
   owner->running=false;assert(!rtl_omci_stop(owner));
   assert(engine_puts==1 && ni.engine_users==1 && ni.host_active);
   /* A partial PUC queue triggers the real internal recovery producer
    * after that close; it is not admitted through the down netdev qdisc. */
   assert(!rtl_gpon_drain_probe(&pon));
  } else {
   /* OAM and business netdevs use the same final-free invariant. Neither
    * depends on ndo_stop being invoked a second time during teardown. */
   owner->running=false;ni.engine_users=1;
   u8 bytes[64]={};struct sk_buff s={.data=bytes,.len=64};
   assert(rtl9617c_ni_transmit(&parent,owner,&s,NULL)==NETDEV_TX_OK && s.freed);
  }
  assert(ni.dma.write==1 && ni.dma.owners[0]==owner);
  assert(get32(ni.dma.memory+RTL_DMA_COUNT*sizeof(struct rtl_dma_descriptor)+4)==64);
  complete(&ni,&lan);
  assert(ni.dma.read==0 && ni.dma.owners[0]==owner); /* Retained prefetch. */
  submit_lan(&ni,&lan);assert(ni.dma.owners[1]==&lan);
  unsigned before_read=ni.dma.read,before_write=ni.dma.write,puts=engine_puts;
  /* Removal has synchronized recovery/IRQ producers. Its last queued
   * descriptor is still retained; no hardware drain is promised. */
  if(!role)rtl_pon_omci_remove(&pon);
  else {unregister_netdev(owner);rtl_oam_free(owner);}
  assert(netdev_frees==1 && !ni.tx_lock && lock_count);
  assert(ni.engine_users==1 && ni.host_active && engine_puts==puts);
  assert(ni.dma.read==before_read && ni.dma.write==before_write && ni.dma.owners[1]==&lan);
  /* Later LAN traffic advances completion beyond the retained PON slot.
   * Old teardown writes owner->stats into freed memory here under ASan. */
  for(unsigned n=0;n<3;n++)submit_lan(&ni,&lan);
  complete(&ni,&lan);
  assert(ni.dma.read==ni.dma.write-2 && lan.stats.tx_packets==2 && lan.stats.tx_bytes==128);
  assert(!ni.dma.owners[0]);forget_checks++;
  assert(fe_removes==(role==2) && !ni_kicks);
  free(ni.dma.memory);free(ni.dma.registers);
 }
 assert(forget_checks==3);
 puts("PON DMA owner: actual GPON probe after OMCI down, retained prefetch, OMCI/OAM/business free and later LAN completion passed; shared engine and unrelated owner preserved");
}
'''


def run(label, cleanup, directory, expect_pass):
    source, executable = directory / (label + '.c'), directory / label
    source.write_text(fixture + functions + cleanup + tests)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(source), '-o', str(executable)], check=True)
    result = subprocess.run([str(executable)], capture_output=True, text=True)
    if expect_pass:
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout, end='')
    else:
        assert result.returncode != 0, label + ' unexpectedly passed'
        assert 'heap-use-after-free' in result.stderr, result.stdout + result.stderr
        print(label + ': rejected with ASan heap-use-after-free in production DMA completion')


with tempfile.TemporaryDirectory(prefix='pon-dma-owner-', dir=root / 'artifacts') as work:
    directory = Path(work)
    run('fixed', destructors, directory, True)
    if args.mutants:
        omci_forget = '\trtl9617c_ni_forget_tx(pon->ni_dev, pon->omci_device);\n'
        oam_forget = ' rtl9617c_ni_forget_tx(port->pon->ni_dev,dev);\n'
        assert omci_forget in destructors and oam_forget in destructors
        run('old-omci-dma-owner', destructors.replace(omci_forget, '', 1), directory, False)
        run('missing-oam-dma-owner', destructors.replace(oam_forget, '', 1), directory, False)
