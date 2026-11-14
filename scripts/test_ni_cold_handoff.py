#!/usr/bin/env python3
"""Execute NI cold publication, retry and remove serialization boundaries.

Uses production publish/handoff/open/remove helpers and the exact probe
publication tail. Registering the first LAN immediately models a netifd open.
Mutexes and competing handoff/removal calls use real pthreads; FE/MMIO and
kernel service APIs remain instrumented boundaries, not hardware emulation.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (drivers / 'rtl9617c-xram.c').read_text()
pon = (drivers / 'rtl9617c-pon.c').read_text()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mutants', action='store_true')
args = parser.parse_args()


def function(text, name):
    match = re.search(r'(?m)^(?:static\s+)?(?:inline\s+)?[\w *]+\b' + name +
                      r'\([^;{}]*\)\s*\{', text)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]


probe = function(source, 'rtl_probe')
assert '"realtek,pon-cold-handoff"' in probe
assert probe.index('mutex_init(&priv->fabric_lock)') < probe.index('platform_set_drvdata(pdev, netdev)')
probe_tail = probe[probe.index('\tplatform_set_drvdata(pdev, netdev);'):probe.index('\nfree_dma:')]
assert 'rtl_register_lans(' not in probe and 'sysfs_create_groups(' not in probe
pon_probe = function(pon, 'rtl9617c_pon_probe')
for boundary in ('platform_get_irq(', 'rtl_pon_mpcp_init(', 'rtl_pon_oam_init(', 'rtl_pon_omci_init('):
    assert pon_probe.index('rtl_pon_cold_handoff(pon)') < pon_probe.index(boundary)
pon_handoff = function(pon, 'rtl_pon_cold_handoff')
assert pon_handoff.index('rtl_pon_cold_rx_gate(') < pon_handoff.index('readl_poll_timeout(') < pon_handoff.index('rtl9617c_ni_cold_handoff(')
assert pon_probe.index('rtl_pon_cold_handoff(pon)') < pon_probe.index('"realtek,optical-front-end"')

common = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define EPROBE_DEFER 517
#define HZ 100
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) ((x)=(y))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define rcu_assign_pointer(x,y) ((x)=(y))
struct mutex {pthread_mutex_t native;};
struct device {void *data;int kobj;};
struct platform_device {struct device dev;};
struct rtl_xram;
struct net_device {struct rtl_xram *priv;};
struct rtl_fe {int unused;};
struct rtl_ni_owner {bool exposed;};
struct rtl_xram {
 struct mutex fabric_lock;
 bool cold_handoff_required,provider_ready,fabric_managed,removing,engine_poisoned;
 bool native_groups_created,irq_requested;
 int fabric_error,mib_work,lan4_ready,lan4_phy,lan4_work,tx_lock,rx_irq;
 unsigned engine_users;
 struct net_device *netdev,*ports[5];struct rtl_fe *fe;struct rtl_ni_owner *owner;
 struct {void *pon;} qm;
 struct {void *owners[64];} dma;
 struct {int unused;} napi;
};
static struct rtl_xram *current;
static pthread_mutex_t gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static _Thread_local int held,role;
static bool baseline_safe,block_baseline,baseline_entered,allow_baseline;
static bool remove_attempted,block_remove,remove_entered,allow_remove,handoff_attempted;
static int baseline_result,sysfs_result;
static unsigned baselines,registrations,sysfs_calls,mib_calls,exposes,opens,stops,unregisters,removed;
static void mutex_lock(struct mutex *lock){
 pthread_mutex_lock(&gate);
 if(role==2)remove_attempted=true;
 if(role==3)handoff_attempted=true;
 pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);
 assert(!pthread_mutex_lock(&lock->native));held++;
}
static void mutex_unlock(struct mutex *lock){assert(held==1);held--;assert(!pthread_mutex_unlock(&lock->native));}
static void *dev_get_drvdata(struct device *dev){return dev->data;}
static struct net_device *platform_get_drvdata(struct platform_device *p){return p->dev.data;}
static void platform_set_drvdata(struct platform_device *p,void *data){p->dev.data=data;}
static struct rtl_xram *netdev_priv(struct net_device *dev){return dev->priv;}
static int rtl_fe_fabric_cold_prepare(struct rtl_fe *fe){
 (void)fe;assert(held && !current->provider_ready);
 assert(!registrations && !sysfs_calls && !mib_calls);baselines++;
 pthread_mutex_lock(&gate);baseline_entered=true;pthread_cond_broadcast(&changed);
 while(block_baseline && !allow_baseline)pthread_cond_wait(&changed,&gate);
 pthread_mutex_unlock(&gate);
 if(baseline_result>=0)baseline_safe=true;
 return baseline_result;
}
static void rtl_ni_owner_expose(struct rtl_ni_owner *owner){assert(held && baseline_safe);owner->exposed=true;exposes++;}
#define dev_warn(...) ((void)0)
#define dev_info(...) ((void)0)
static void wait_for_completion(int *completion){assert(*completion);}
static int rtl_engine_start(struct rtl_xram *priv){
 assert(priv->provider_ready && (!priv->cold_handoff_required || baseline_safe));opens++;return 0;
}
static int rtl_engine_get(struct rtl_xram *priv);
static void rtl_register_lans(struct rtl_xram *priv,struct device *dev){
 (void)dev;assert(priv->provider_ready);
 assert(!priv->cold_handoff_required || baseline_safe);
 registrations++;priv->ports[0]=priv->netdev;priv->lan4_ready=1;
 /* The register_netdevice RTNL boundary can immediately deliver ndo_open. */
 assert(!rtl_engine_get(priv));assert(priv->engine_users==1);
}
static const int rtl_native_groups[1];
static int sysfs_create_groups(int *kobj,const int *groups){
 (void)kobj;(void)groups;assert(current->provider_ready && registrations==1);sysfs_calls++;return sysfs_result;
}
static void schedule_delayed_work(int *work,int delay){
 (void)work;assert(delay==HZ && current->provider_ready && registrations==1);mib_calls++;
}
static void flush_work(int *work){(void)work;assert(held && current->removing && !current->provider_ready);}
static void cancel_delayed_work_sync(int *work){
 (void)work;assert(held && current->removing && !current->provider_ready);
 pthread_mutex_lock(&gate);remove_entered=true;pthread_cond_broadcast(&changed);
 while(block_remove && !allow_remove)pthread_cond_wait(&changed,&gate);
 pthread_mutex_unlock(&gate);
}
static void sysfs_remove_groups(int *kobj,const int *groups){(void)kobj;(void)groups;assert(held && !current->provider_ready);}
static void rtl_unregister_lan(struct rtl_xram *priv,unsigned port){
 assert(held && priv->removing && !priv->provider_ready);priv->ports[port]=NULL;unregisters++;
}
static void rtnl_lock(void){}
static void rtnl_unlock(void){}
static void rtl_engine_stop(struct rtl_xram *priv){(void)priv;assert(held);stops++;}
#define spin_lock_irqsave(p,f) ((void)(p),(f)=0)
#define spin_unlock_irqrestore(p,f) ((void)(p),(void)(f))
static void rtl_engine_poison(struct rtl_xram *priv){priv->engine_poisoned=true;}
static void synchronize_net(void){}
static void free_irq(int irq,struct rtl_xram *priv){(void)irq;(void)priv;}
static bool rtl_ni_release_dma(struct rtl_xram *priv,struct device *dev){
 (void)priv;(void)dev;assert(held);return false; /* retained owner, no fixture free */
}
static void netif_napi_del(void *napi){(void)napi;removed++;}
static void rtl_ni_owner_release(struct rtl_ni_owner *owner){(void)owner;assert(false);}
static void free_netdev(struct net_device *dev){(void)dev;assert(false);}
'''
functions = '\n'.join(function(source, name) for name in (
    'rtl_engine_get', 'rtl_ni_publish', 'rtl9617c_ni_cold_handoff', 'rtl_remove'))
publication = '''
static int probe_publication_tail(struct platform_device *pdev) {
 struct device *dev=&pdev->dev;
 struct net_device *netdev=current->netdev;
 struct rtl_xram *priv=current;
''' + probe_tail + '\n}\n'
main = r'''
static struct platform_device platform;
static struct net_device netdev;
static struct rtl_ni_owner owner;
static struct rtl_fe fe;
static void init(struct rtl_xram *priv,bool required){
 memset(priv,0,sizeof(*priv));assert(!pthread_mutex_init(&priv->fabric_lock.native,NULL));
 memset(&platform,0,sizeof(platform));memset(&owner,0,sizeof(owner));
 current=priv;netdev.priv=priv;priv->netdev=&netdev;priv->fe=&fe;priv->owner=&owner;
 priv->cold_handoff_required=required;
 baseline_result=sysfs_result=0;baseline_safe=false;
 baselines=registrations=sysfs_calls=mib_calls=exposes=opens=stops=unregisters=removed=0;
 block_baseline=baseline_entered=allow_baseline=false;
 block_remove=remove_entered=allow_remove=false;remove_attempted=handoff_attempted=false;
 assert(!probe_publication_tail(&platform));
 if(required)assert(!priv->provider_ready && !registrations && !sysfs_calls && !mib_calls);
}
static void done(struct rtl_xram *priv){assert(!pthread_mutex_destroy(&priv->fabric_lock.native));}
static void *handoff_thread(void *arg){role=(int)(intptr_t)arg;return (void *)(intptr_t)rtl9617c_ni_cold_handoff(&platform.dev);}
static void *remove_thread(void *arg){(void)arg;role=2;rtl_remove(&platform);return NULL;}
static void wait_flag(bool *flag){pthread_mutex_lock(&gate);while(!*flag)pthread_cond_wait(&changed,&gate);pthread_mutex_unlock(&gate);}
static void release_flag(bool *flag){pthread_mutex_lock(&gate);*flag=true;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);}
int main(void){
 struct rtl_xram p;unsigned cases=0;
 assert(rtl9617c_ni_cold_handoff(&platform.dev)==-EPROBE_DEFER);cases++;
 /* DT-off boards publish normally; a flagged board remains completely private. */
 init(&p,false);assert(p.provider_ready && registrations==1 && opens==1 && !baselines);done(&p);cases++;
 init(&p,true);assert(rtl_engine_get(&p)==-EPROBE_DEFER && !opens);done(&p);cases++;
 for(int status=-2;status<=1;status++){
  init(&p,true);baseline_result=status;int ret=rtl9617c_ni_cold_handoff(&platform.dev);
  if(status<0){
   assert(ret==status && p.fabric_error==status && !p.provider_ready && !p.fabric_managed);
   assert(!registrations && !sysfs_calls && !mib_calls && !opens && !owner.exposed);
   baseline_result=0;assert(!rtl9617c_ni_cold_handoff(&platform.dev));assert(baselines==2);
  }else{
   assert(!ret && p.provider_ready && p.fabric_error==status);
   assert(p.fabric_managed==(status==0) && owner.exposed==(status==0));
  }
  assert(registrations==1 && sysfs_calls==1 && mib_calls==1 && opens==1);
  unsigned before=baselines;assert(!rtl9617c_ni_cold_handoff(&platform.dev));
  assert(baselines==before && registrations==1 && mib_calls==1);done(&p);cases++;
 }
 init(&p,true);sysfs_result=-ENOMEM;assert(!rtl9617c_ni_cold_handoff(&platform.dev));
 assert(p.provider_ready && !p.native_groups_created && registrations==1 && mib_calls==1);done(&p);cases++;
 for(unsigned mask=1;mask<4;mask++){
  init(&p,true);p.removing=!!(mask&1);p.engine_poisoned=!!(mask&2);
  assert(rtl9617c_ni_cold_handoff(&platform.dev)==-EIO);
  assert(!baselines && !registrations && !sysfs_calls && !mib_calls);done(&p);cases++;
 }
 /* Two real concurrent consumers share one baseline/publication transaction. */
 {
  pthread_t a,b;void *ra,*rb;init(&p,true);block_baseline=true;
  assert(!pthread_create(&a,NULL,handoff_thread,(void *)1));wait_flag(&baseline_entered);
  assert(!pthread_create(&b,NULL,handoff_thread,(void *)3));wait_flag(&handoff_attempted);
  assert(!registrations && !p.provider_ready);release_flag(&allow_baseline);
  assert(!pthread_join(a,&ra) && !pthread_join(b,&rb));assert(!ra && !rb);
  assert(baselines==1 && registrations==1 && opens==1 && sysfs_calls==1 && mib_calls==1);done(&p);cases++;
 }
 /* Removal cannot withdraw a half-published owner while handoff holds its lock. */
 {
  pthread_t a,b;init(&p,true);block_baseline=true;
  assert(!pthread_create(&a,NULL,handoff_thread,(void *)1));wait_flag(&baseline_entered);
  assert(!pthread_create(&b,NULL,remove_thread,NULL));wait_flag(&remove_attempted);
  assert(!p.removing && !removed && !registrations);release_flag(&allow_baseline);
  assert(!pthread_join(a,NULL) && !pthread_join(b,NULL));
  assert(p.removing && !p.provider_ready && p.engine_poisoned && !platform.dev.data);
  assert(registrations==1 && removed==1 && unregisters==5 && stops==1);done(&p);cases++;
 }
 /* A handoff already waiting behind remove is refused and never republishes. */
 {
  pthread_t a,b;void *result;init(&p,true);block_remove=true;
  assert(!pthread_create(&a,NULL,remove_thread,NULL));wait_flag(&remove_entered);
  assert(!pthread_create(&b,NULL,handoff_thread,(void *)3));wait_flag(&handoff_attempted);
  assert(!baselines && !registrations);release_flag(&allow_remove);
  assert(!pthread_join(a,NULL) && !pthread_join(b,&result));assert((intptr_t)result==-EIO);
  assert(!p.provider_ready && !baselines && !registrations && !sysfs_calls && !mib_calls);done(&p);cases++;
 }
 printf("NI cold handoff: %u runtime cases; probe publication, immediate open, refusal/retry, idempotence, concurrent handoff/remove passed\n",cases);
}
'''
unit = common + functions + publication + main
variants = [('production', unit, True)]
if args.mutants:
    variants += [
        ('publish_before_ready', unit.replace('WRITE_ONCE(priv->provider_ready, true);\n\trtl_register_lans(priv, dev);',
                                             'rtl_register_lans(priv, dev);\n\tWRITE_ONCE(priv->provider_ready, true);', 1), False),
        ('ignore_baseline_failure', unit.replace('if (ret < 0)\n\t\t\tgoto out;', 'if (false)\n\t\t\tgoto out;', 1), False),
        ('repeat_publication', unit.replace('if (READ_ONCE(priv->provider_ready))\n\t\tgoto out;',
                                           'if (false)\n\t\tgoto out;', 1), False),
        ('publish_flagged_probe', unit.replace('if (!priv->cold_handoff_required)\n\t\trtl_ni_publish(priv, dev);',
                                              'if (true)\n\t\trtl_ni_publish(priv, dev);', 1), False),
        ('omit_provider_open_gate', unit.replace('if (priv->cold_handoff_required && !READ_ONCE(priv->provider_ready))',
                                               'if (false)', 1), False),
    ]
with tempfile.TemporaryDirectory(prefix='ni-cold-handoff-') as directory:
    directory = Path(directory)
    for name, text, passed in variants:
        assert name=='production' or text != unit, name
        cfile,binary=directory/(name+'.c'),directory/name
        cfile.write_text(text)
        subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',
                        '-O1','-g','-pthread','-fsanitize=address,undefined',str(cfile),'-o',str(binary)],check=True)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
        if passed:
            assert result.returncode==0,result.stdout+result.stderr
            print(result.stdout,end='')
        else:
            assert result.returncode!=0 and 'Assertion' in result.stderr,(name,result.stderr)
            print(name+': detected by runtime oracle')
print('NI/PON production order checked: DT flag gates LAN publication; PON RX handoff precedes IRQ and OAM/OMCI publication')
