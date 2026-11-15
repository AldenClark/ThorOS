#!/usr/bin/env python3
"""Execute PON probe-tail/normal-remove lifetime with NI callback fault injection.

The production OMCI init/remove and shared endpoint wake functions are compiled
unchanged. A concurrent NI timer callback is injected at each netdev free; its
owner may already be running for unrelated LAN traffic when PON probe fails.
This is an ASan/UBSan host lifetime test, not a physical IRQ/ASIC test.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
driver = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mutants', action='store_true')
args = parser.parse_args()
pon_source = (driver / 'rtl9617c-pon.c').read_text()
oam_source = (driver / 'rtl9617c-pon-oam.c').read_text()
omci_source = (driver / 'rtl9617c-pon-omci.c').read_text()


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


probe = function(pon_source, 'rtl9617c_pon_probe')
tail = ('static int probe_transports(struct rtl9617c_pon *pon, struct platform_device *pdev) {\n'
        ' int ret;\n' + probe[probe.index('\tret = rtl_pon_oam_init(pon);'):])
wake = function(oam_source, 'rtl_oam_wake')
omci_init = function(omci_source, 'rtl_pon_omci_init')
omci_remove = function(omci_source, 'rtl_pon_omci_remove')
oam_remove = function(oam_source, 'rtl_pon_oam_remove')
normal_remove = function(pon_source, 'rtl9617c_pon_remove')

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define EPROBE_DEFER 517
#define NET_NAME_UNKNOWN 0
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x)>=(uintptr_t)-4095)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define rcu_dereference(x) (x)
struct rtl9617c_pon;
struct net_device {
 struct rtl9617c_pon *priv;
 bool running,stopped,registered,omci;
};
struct rtl9617c_ni_endpoint {struct net_device *netdev;};
struct rtl9617c_pon {
 struct rtl9617c_ni_endpoint oam_endpoint;
 struct net_device *omci_device,*oam_devices[32],*data_devices[32];
 void *omci_kdf,*omci_cmac,*ni_dev,*dev;
 int omci_key_lock;
};
struct platform_device {struct rtl9617c_pon *data;};
static struct rtl9617c_pon *active;
static bool endpoint_attached;
static unsigned fault,crypto_allocs,crypto_live,netdev_live,graces,callbacks,wakes,stops;
static unsigned detach_count,oam_remove_count,omci_stop_count,shutdown_count;
static bool netif_running(struct net_device *d){return d->running;}
static bool netif_queue_stopped(struct net_device *d){return d->stopped;}
static void netif_wake_queue(struct net_device *d){d->stopped=false;wakes++;}
static void rtl_oam_wake(struct rtl9617c_ni_endpoint *endpoint);
static void ni_timer_callback(void) {
 if(endpoint_attached) {callbacks++;rtl_oam_wake(&active->oam_endpoint);}
}
static void free_netdev(struct net_device *d) {
 assert(d && !d->registered && netdev_live);
 netdev_live--;free(d);
 /* A timer is independent of this netdev's registration. Inject it on
  * another CPU before the caller clears pon->omci_device. A stale pointer
  * is an actual ASan read-after-free in production rtl_oam_wake(). */
 ni_timer_callback();
}
static void rtl_omci_setup(struct net_device *d){d->omci=true;}
static struct net_device *alloc_netdev(size_t n,const char *name,int assign,
                                     void (*setup)(struct net_device *)) {
 (void)name;assert(n==sizeof(active) && assign==NET_NAME_UNKNOWN);
 if(fault==2)return NULL;
 struct net_device *d=calloc(1,sizeof(*d));assert(d);netdev_live++;setup(d);return d;
}
static void *crypto_alloc_shash(const char *name,int type,int mask) {
 (void)name;assert(!type && !mask);crypto_allocs++;
 if((fault==3 && crypto_allocs==1)||(fault==4 && crypto_allocs==2))return ERR_PTR(-ENODEV);
 void *p=malloc(1);assert(p);crypto_live++;return p;
}
static void crypto_free_shash(void *p){assert(p && !IS_ERR(p) && crypto_live);free(p);crypto_live--;}
static void spin_lock_init(int *lock){*lock=0;}
static void *netdev_priv(struct net_device *d){return &d->priv;}
#define SET_NETDEV_DEV(d,p) ((void)(d),(void)(p))
static void netif_carrier_off(struct net_device *d){assert(d);}
static int register_netdev(struct net_device *d) {
 assert(d->omci && !d->registered && d->priv==active);
 if(fault==5)return -EIO;
 d->registered=true;return 0;
}
static void unregister_netdev(struct net_device *d) {
 assert(d && d->registered);d->registered=false;d->running=false;
 /* unregister's own grace period cannot stop a future NI callback. */
 ni_timer_callback();
}
static int rtl_pon_oam_init(struct rtl9617c_pon *p) {
 assert(p==active && !endpoint_attached);
 if(fault==1)return -ENOMEM;
 struct net_device *d=calloc(1,sizeof(*d));assert(d);netdev_live++;
 d->registered=d->running=d->stopped=true;
 p->oam_endpoint.netdev=p->oam_devices[0]=d;endpoint_attached=true;
 return 0;
}
static void rtl9617c_ni_pon_detach(void *dev) {
 (void)dev;assert(endpoint_attached);
 /* Existing reader finishes before detach's synchronize_net returns. */
 ni_timer_callback();endpoint_attached=false;graces++;detach_count++;
}
static void rtl_pon_itu_paths_remove(struct rtl9617c_pon *p){assert(p==active && !endpoint_attached);}
static void rtl_pon_oam_resize(struct rtl9617c_pon *p,unsigned count) {
 assert(p==active && count==0 && !endpoint_attached);oam_remove_count++;
 struct net_device *d=p->oam_devices[0];assert(d);p->oam_devices[0]=NULL;
 unregister_netdev(d);free_netdev(d);
}
static void rtl_pon_dying_gasp_stop(struct rtl9617c_pon *p){assert(p==active);omci_stop_count++;}
static void rtl9617c_ni_forget_tx(void *ni,struct net_device *d) {
 (void)ni;assert(d && !d->registered);
}
static int rtl_pon_dying_gasp_init(struct rtl9617c_pon *p,struct platform_device *pdev) {
 assert(p==active && pdev->data==p && p->omci_device && endpoint_attached);
 /* LAN ring pressure can request a wake even if OMCI has never opened. */
 p->omci_device->stopped=true;ni_timer_callback();
 if(fault==6)return -EPROBE_DEFER;
 if(fault==7)return -EBUSY;
 return 0;
}
static struct rtl9617c_pon *platform_get_drvdata(struct platform_device *p){return p->data;}
static void rtl9617c_pon_shutdown(struct platform_device *p) {
 assert(p->data==active && endpoint_attached);shutdown_count++;
}
'''

tests = r'''
int main(void) {
 const int errors[]={0,-ENOMEM,-ENOMEM,-ENODEV,-ENODEV,-EIO,-EPROBE_DEFER,-EBUSY};
 for(fault=0;fault<8;fault++) {
  struct rtl9617c_pon pon={};struct platform_device pdev={.data=&pon};
  active=&pon;endpoint_attached=false;
  crypto_allocs=crypto_live=netdev_live=graces=callbacks=wakes=stops=0;
  detach_count=oam_remove_count=omci_stop_count=shutdown_count=0;
  assert(probe_transports(&pon,&pdev)==errors[fault]);
  if(!fault) {
   assert(endpoint_attached && pon.omci_device && crypto_live==2 && netdev_live==2);
   pon.omci_device->running=pon.omci_device->stopped=true;
   ni_timer_callback();assert(!pon.omci_device->stopped);
   rtl9617c_pon_remove(&pdev);
   assert(shutdown_count==1 && omci_stop_count==1);
  } else {
   assert(!shutdown_count);
   assert(omci_stop_count==(fault>=6));
  }
  assert(!endpoint_attached && !netdev_live && !crypto_live && !pon.omci_device);
  assert(detach_count==(fault!=1) && graces==detach_count && oam_remove_count==detach_count);
  assert(!pon.oam_devices[0]);
 }
 puts("PON probe unwind: OAM/OMCI allocation, crypto, registration, deferred/failed Dying Gasp and normal remove preserve errors and retire shared NI callbacks before free");
}
'''


def run(label, probe_tail, directory, expect_pass):
    source = directory / (label + '.c')
    executable = directory / label
    source.write_text(fixture + wake + omci_init + omci_remove + oam_remove +
                      probe_tail + normal_remove + tests)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(source), '-o', str(executable)], check=True)
    result = subprocess.run([str(executable)], capture_output=True, text=True)
    if expect_pass:
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout, end='')
    else:
        assert result.returncode != 0, 'old unsafe cleanup order unexpectedly passed'
        assert 'heap-use-after-free' in result.stderr, result.stdout + result.stderr
        print('Rejected old OMCI-before-endpoint cleanup with ASan heap-use-after-free in production NI wake callback')


with tempfile.TemporaryDirectory(prefix='pon-probe-unwind-', dir=root / 'artifacts') as work:
    directory = Path(work)
    run('fixed', tail, directory, True)
    if args.mutants:
        order = '\t\trtl_pon_oam_remove(pon);\n\t\trtl_pon_omci_remove(pon);'
        assert order in tail
        mutant = tail.replace(order, '\t\trtl_pon_omci_remove(pon);\n\t\trtl_pon_oam_remove(pon);', 1)
        run('old-cleanup-order', mutant, directory, False)
