#!/usr/bin/env python3
"""Exercise actual control transactions and MAC updates with controlled threads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
relative = Path('port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek')
headers = root / relative
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--revision')
parser.add_argument('--case', choices=('transactions', 'address', 'serdes-sync', 'epon-policy'), action='append')
parser.add_argument('--mutants', action='store_true', help='Reject broken PON namespace/address/EPON publication variants')
args = parser.parse_args()


def read(name):
    if args.revision:
        return subprocess.check_output(['git', 'show', f'{args.revision}:{relative / name}'], cwd=root, text=True)
    return (headers / name).read_text()


def function(text, name):
    start = re.search(r'^.*\b' + re.escape(name) + r'\([^;]*?\)\s*\{', text, re.M).start()
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'


common = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtl9617c-pon-mode.h"
#include "rtl9617c-mpcp-backoff.h"
#include "rtl9617c-pon-data.h"
typedef uint64_t u64;typedef uint32_t u32;typedef uint16_t u16;typedef uint8_t u8;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h))) & (~0U<<(l)))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
struct mutex {pthread_mutex_t native;bool held;};
static pthread_t starter;
static pthread_mutex_t gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static bool window,attempted,finished;
static void mutex_lock(struct mutex *lock) {
    if (pthread_equal(pthread_self(),starter)) {
        pthread_mutex_lock(&gate);attempted=true;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);
    }
    assert(pthread_mutex_lock(&lock->native)==0);lock->held=true;
}
static void mutex_unlock(struct mutex *lock) {assert(lock->held);lock->held=false;assert(pthread_mutex_unlock(&lock->native)==0);}
static bool mutex_trylock(struct mutex *lock) {
    int ret=pthread_mutex_trylock(&lock->native);
    if(ret==EBUSY)return false;
    assert(ret==0);lock->held=true;return true;
}
#define lockdep_assert_held(lock) assert((lock)->held)
struct delayed_work {bool pending;};
struct net_device {bool carrier,control;};
struct net {unsigned int unused;};
static struct net policy_net;
static unsigned int policy_depth,policy_begins,policy_ends,rcu_depth;
static bool policy_tracking,guard_present=true;
static void (*write_check)(u32 value,void *p);
static u32 (*read_hook)(const void *p,u32 value);
static void (*policy_end_check)(void);
struct rtl9617c_pon {
    struct mutex lock,control_lock;enum rtl_pon_mode mode;
    void *mac,*control,*epon_control,*gpon_control,*serdes_init,*optical_control,*top_irq,*dev,*ni_dev;
    bool mpcp_enabled,mpcp_configured,mac_prepared,traffic_enabled,serdes_configured,gearbox_ready,rx_synced,puc_configured,pdc_configured,fe_enabled,fe_cpu_path,xgpon_pending_valid;
    u32 registered,waiting,serdes_status;int sync_result,serdes_error,serdes_last_config_error,mpcp_irq,cleanup_error,policy_error;
    u64 serdes_attempts,serdes_first_start_ns,serdes_last_start_ns,serdes_last_finished_ns;
    uint64_t epon_epoch,epon_llid_epoch[32];
    u32 epon_crypto_llids,epon_sync_failures;
    u32 epon_holdover_active,epon_holdover_pending;
    u32 epon_holdover_enabled,epon_llid_cleanup,last_mpcp_irq;
    unsigned int epon_holdover_ms[32],register_frames;
    unsigned long epon_holdover_start[32];
    int epon_holdover_error,epon_llid_cleanup_error,epon_crypto_error,pdc_error;
    u8 pdc_source[64];
    struct net_device *data_devices[32],*oam_devices[32];
    unsigned int epon_tx_action;
    unsigned long epon_health_at;
    int *tx_disable;
    unsigned int llid_count,los_invert,profile_rows;u8 onu_mac[6];
    struct rtl_mpcp_backoff backoff;struct delayed_work mpcp_work,serdes_work,epon_tx_work,epon_holdover_work;
};
static struct rtl9617c_pon *current;
static struct net *rtl9617c_switch_policy_begin(struct net_device *dev) {
    if(!dev || !guard_present)return NULL;
    policy_depth++;policy_begins++;return &policy_net;
}
static void rtl9617c_switch_policy_end(struct net *policy) {
    if(!policy)return;
    assert(policy==&policy_net && policy_depth);policy_depth--;policy_ends++;
    if(!policy_depth && policy_end_check)policy_end_check();
}
static void rcu_read_lock(void) {rcu_depth++;}
static void rcu_read_unlock(void) {assert(rcu_depth);rcu_depth--;}
#define rcu_dereference(p) (p)
static unsigned long jiffies;
#define msecs_to_jiffies(ms) (ms)
static int rtl_pon_epon_crypto_forget(struct rtl9617c_pon *pon,u32 mask)
{if(policy_tracking && mask)assert(policy_depth);pon->epon_crypto_llids &= ~mask;return 0;}
int rtl_pon_stop_locked(struct rtl9617c_pon *pon);
static int rtl_pon_itu_paths_invalidate(struct rtl9617c_pon *pon,enum rtl_pon_mode mode){(void)mode;assert(pon->lock.held);return pon->policy_error;}
static int rtl_pon_fe_stop_locked(struct rtl9617c_pon *pon) {
    lockdep_assert_held(&pon->control_lock);
    if(pon->cleanup_error)return pon->cleanup_error;
    pon->fe_enabled=pon->fe_cpu_path=false;return 0;
}
static void gpiod_set_value_cansleep(int *gpio,int value) {*gpio=value;}
static void rtl_pon_gpon_stop_locked(struct rtl9617c_pon *pon) {(void)pon;}
static void rtl_pon_xgpon_stop_locked(struct rtl9617c_pon *pon) {(void)pon;}
static unsigned int canceled;
static unsigned int data_resets;
static u32 stale_puc,stale_pdc;
static void *state_reader(void *unused) {
    (void)unused;mutex_lock(&current->lock);mutex_unlock(&current->lock);return NULL;
}
static void cancel_delayed_work_sync(struct delayed_work *work) {
    /* Model a running callback that needs the state mutex to finish. */
    pthread_t worker;assert(!current->lock.held);
    assert(pthread_create(&worker,NULL,state_reader,NULL)==0);
    assert(pthread_join(worker,NULL)==0);work->pending=false;canceled++;
}
static void schedule_delayed_work(struct delayed_work *work,unsigned int delay) {(void)delay;work->pending=true;}
#define HZ 1000
#define msleep(ms) ((void)0)
#define udelay(us) ((void)0)
#define dev_info(...) ((void)0)
static u64 test_boottime_ns=100000000;
static u64 ktime_get_boottime_ns(void) {return test_boottime_ns+=1000000;}
static const char *rtl_pon_mode_name(enum rtl_pon_mode mode) {return rtl_pon_modes[mode].name;}
static int sysfs_emit(char *buf,const char *fmt,...) {
    va_list args;va_start(args,fmt);int ret=vsnprintf(buf,4096,fmt,args);va_end(args);assert(ret>=0 && ret<4096);return ret;
}
static u32 readl(const void *p) {u32 value;memcpy(&value,p,4);return read_hook?read_hook(p,value):value;}
static void writel(u32 value,void *p) {
    if(write_check)write_check(value,p);
    if(current && p==current->control) {
        u32 previous=readl(p);
        if((previous&BIT(8)) && !(value&BIT(8))) {stale_puc=0;data_resets++;}
        if((previous&BIT(9)) && !(value&BIT(9)))stale_pdc=0;
    }
    memcpy(p,&value,4);
}
static void rtl_pon_update(void *p,u32 mask,u32 value) {writel((readl(p)&~mask)|(value&mask),p);}
#define readl_poll_timeout(addr,status,condition,delay,timeout) ({(status)=readl(addr);(condition)?0:-ETIMEDOUT;})
static int is_valid_ether_addr(const u8 *mac) {return !(mac[0]&1) && memcmp(mac,"\0\0\0\0\0\0",6);}
static u16 get_unaligned_be16(const u8 *p) {return p[0]*256+p[1];}
static u32 get_unaligned_be32(const u8 *p) {return (u32)p[0]<<24|(u32)p[1]<<16|p[2]<<8|p[3];}
static void rtl_pon_oam_carrier(struct rtl9617c_pon *pon) {assert(pon->lock.held);}
static void synchronize_irq(int irq) {(void)irq;assert(!current->lock.held);}
struct firmware {};
static const struct firmware firmware;
static int firmware_failure,profile_failure;
static int request_firmware_direct(const struct firmware **fw,const char *name,void *dev) {
    (void)name;(void)dev;if(firmware_failure)return firmware_failure;*fw=&firmware;return 0;
}
static void release_firmware(const struct firmware *fw) {assert(fw==&firmware);}
static int rtl_pon_profile_validate(const struct firmware *fw) {(void)fw;return profile_failure;}
static void rtl_pon_profile_load(struct rtl9617c_pon *pon,const struct firmware *fw) {(void)fw;pon->profile_rows=1;}
static int rtl_pon_burst_polarity(struct rtl9617c_pon *pon,unsigned int page) {(void)pon;(void)page;return 0;}
static void rtl_pon_gearbox_release(struct rtl9617c_pon *pon) {pon->gearbox_ready=true;}
static int rtl_pon_epon_traffic_locked(struct rtl9617c_pon *pon,bool enable) {
    assert(!enable);pon->traffic_enabled=false;
    int ret=(pon->fe_enabled||pon->fe_cpu_path)?rtl_pon_fe_stop_locked(pon):0;
    /* Cut exactly after stop, while another thread tries public MPCP start. */
    pthread_mutex_lock(&gate);window=true;pthread_cond_broadcast(&changed);
    while(!attempted) pthread_cond_wait(&changed,&gate);
    if (!pon->control_lock.held) while(!finished) pthread_cond_wait(&changed,&gate);
    pthread_mutex_unlock(&gate);return ret;
}
static int rtl_pon_epon_traffic(struct rtl9617c_pon *pon,bool enable) {return rtl_pon_epon_traffic_locked(pon,enable);}
'''

timing_model = r'''
struct device {void *data;};
struct device_attribute {int unused;};
static void *dev_get_drvdata(struct device *dev) {return dev->data;}
'''

transaction_test = r'''
static int start_result;
static void *concurrent_start(void *arg) {
    struct rtl9617c_pon *pon=arg;
    pthread_mutex_lock(&gate);while(!window) pthread_cond_wait(&changed,&gate);pthread_mutex_unlock(&gate);
    start_result=rtl_pon_mpcp_configure(pon);
    pthread_mutex_lock(&gate);finished=true;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);return NULL;
}
int main(void) {
    u32 mac[0xc000/4]={},top[2]={},control=0,epon=0,gpon=0,serdes=0,optical=0;int disabled=0;
    struct rtl9617c_pon pon={.mode=RTL_PON_EPON_D10G,.mac=mac,.top_irq=top,
        .control=&control,.epon_control=&epon,.gpon_control=&gpon,.serdes_init=&serdes,.optical_control=&optical,
        .llid_count=1,.mac_prepared=true,.serdes_configured=true,.onu_mac={2,1,2,3,4,5},.tx_disable=&disabled};
    current=&pon;assert(pthread_mutex_init(&pon.lock.native,NULL)==0);assert(pthread_mutex_init(&pon.control_lock.native,NULL)==0);
    mac[PSDS_STATUS/4]=PSDS_SYNC_GOAL;
    for(unsigned int mode=RTL_PON_GPON;mode<RTL_PON_MODE_COUNT;mode++) {
        pon.mode=RTL_PON_EPON_D10G;pon.mac_prepared=true;pon.mpcp_enabled=pon.mpcp_configured=true;
        pon.mpcp_work.pending=true;pon.fe_enabled=true;top[1]=1;window=attempted=finished=false;
        control=0x30f;stale_puc=0xdeadbeef;stale_pdc=0xcafebabe;
        assert(pthread_create(&starter,NULL,concurrent_start,&pon)==0);
        assert(rtl_pon_serdes_configure(&pon,mode)==0);
        assert(pthread_join(starter,NULL)==0);
        assert(start_result<0 && pon.mode==(enum rtl_pon_mode)mode && !pon.mpcp_enabled && !pon.mpcp_configured);
        assert(!pon.mpcp_work.pending && !(top[1]&1) && pon.serdes_work.pending && !pon.fe_enabled);
        assert(!pon.control_lock.held && !pon.lock.held);
        assert(!stale_puc && !stale_pdc && !(control&(BIT(8)|BIT(9))));
    }
    assert(data_resets==3);
    assert(canceled==12); /* SerDes, MPCP, TX restore and holdover per mode. */
    pon.mode=RTL_PON_GPON;control=0x30e;stale_puc=1;stale_pdc=2;
    assert(!rtl_pon_serdes_configure(&pon,RTL_PON_EPON_D10G));
    assert(pon.mode==RTL_PON_EPON_D10G && !stale_puc && !stale_pdc &&
           !(control&(BIT(8)|BIT(9))) && data_resets==4);
    pon.mode=RTL_PON_XGSPON;pon.fe_enabled=true;pon.cleanup_error=-EIO;
    control=0x30e;stale_puc=0x1234;stale_pdc=0x5678;
    assert(rtl_pon_serdes_configure(&pon,RTL_PON_EPON_D10G)==-EIO);
    assert(pon.mode==RTL_PON_XGSPON && pon.fe_enabled && disabled && pon.serdes_error==-EIO);
    assert(stale_puc==0x1234 && stale_pdc==0x5678 && control==0x30e && data_resets==4);
    pon.cleanup_error=0;pon.policy_error=-ENOMEM;
    assert(rtl_pon_serdes_configure(&pon,RTL_PON_EPON_D10G)==-ENOMEM);
    assert(pon.mode==RTL_PON_XGSPON && !pon.fe_enabled && pon.serdes_error==-ENOMEM);
    assert(stale_puc==0x1234 && stale_pdc==0x5678 && control==0x30e && data_resets==4);
    assert(pon.serdes_attempts==6 && pon.serdes_first_start_ns &&
           pon.serdes_last_finished_ns>pon.serdes_last_start_ns);
    u64 first=pon.serdes_first_start_ns,previous=pon.serdes_last_start_ns;
    pon.policy_error=0;firmware_failure=-ENOENT;
    assert(rtl_pon_serdes_configure(&pon,RTL_PON_GPON)==-ENOENT);
    assert(pon.serdes_error==-ENOENT && pon.mode==RTL_PON_XGSPON &&
           control==0x30e && pon.serdes_attempts==7 &&
           pon.serdes_first_start_ns==first && pon.serdes_last_start_ns>previous &&
           pon.serdes_last_finished_ns>pon.serdes_last_start_ns);
    firmware_failure=0;profile_failure=-EINVAL;
    assert(rtl_pon_serdes_configure(&pon,RTL_PON_GPON)==-EINVAL);
    assert(pon.serdes_error==-EINVAL && pon.mode==RTL_PON_XGSPON &&
           control==0x30e && pon.serdes_attempts==8 &&
           pon.serdes_first_start_ns==first &&
           pon.serdes_last_finished_ns>pon.serdes_last_start_ns);
    assert(pon.serdes_last_config_error==-EINVAL);
    /* A later warm XGPON recovery may change the live SerDes error; it
     * cannot change the recorded result of this configuration attempt. */
    pon.serdes_error=-ETIMEDOUT;
    char state[4096];assert(rtl_pon_serdes_timing(&pon,state)>0);
    assert(strstr(state,"schema=1 cached=1 mmio_reads=0 mmio_writes=0"));
    assert(strstr(state,"serdes_timebase=boottime_ns serdes_attempts=8"));
    assert(strstr(state,"serdes_first_start_ns=101000000"));
    assert(strstr(state,"serdes_last_elapsed_ns=1000000"));
    assert(strstr(state,"serdes_last_error=-22"));
    struct device device={.data=&pon};
    mutex_lock(&pon.lock);
    assert(serdes_timing_show(&device,NULL,state)>0);
    assert(strstr(state,"schema=1 available=0 cached=1 mmio_reads=0 mmio_writes=0 reason=busy retryable=1"));
    mutex_unlock(&pon.lock);
    assert(serdes_timing_show(&device,NULL,state)>0);
    assert(strstr(state,"serdes_last_error=-22"));
    puts("Actual SerDes/MPCP transaction: concurrent restart blocked; old PUC/PDC reset before mode handoff; failed FE/NI cleanup preserves old mode and hardware ownership");
    pthread_mutex_destroy(&pon.lock.native);pthread_mutex_destroy(&pon.control_lock.native);
}
'''

sync_model = r'''
#include <stddef.h>
struct work_struct {int unused;};
#define to_delayed_work(p) ((struct delayed_work *)(p))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
'''
sync_test = r'''
int main(void) {
 starter=pthread_self();
 for(unsigned int mode=0;mode<RTL_PON_MODE_COUNT;mode++) {
  u32 mac[0xc000/4]={},epon=0xa5a50001;
  struct rtl9617c_pon pon={.mode=mode,.mac=mac,.epon_control=&epon,.serdes_configured=true,.sync_result=-ETIMEDOUT};
  pthread_mutex_init(&pon.lock.native,NULL);current=&pon;
  mac[PSDS_STATUS/4]=PSDS_SYNC_GOAL|BIT(0);
  rtl_pon_serdes_work((struct work_struct *)&pon.serdes_work);
  assert(!pon.rx_synced && pon.sync_result==-ENOLINK && epon==0xa5a50001);
  mac[PSDS_STATUS/4]=PSDS_SYNC_GOAL&~BIT(12);
  rtl_pon_serdes_work((struct work_struct *)&pon.serdes_work);
  assert(!pon.rx_synced && pon.sync_result==-ENOLINK && epon==0xa5a50001);
  mac[PSDS_STATUS/4]=PSDS_SYNC_GOAL;
  rtl_pon_serdes_work((struct work_struct *)&pon.serdes_work);
  assert(pon.rx_synced && !pon.sync_result && pon.serdes_work.pending);
  assert(epon==(rtl_pon_mode_is_epon(mode)?0xa5a50001U:0xa5a50000U));
  rtl_pon_serdes_work((struct work_struct *)&pon.serdes_work);
  assert(epon==(rtl_pon_mode_is_epon(mode)?0xa5a50001U:0xa5a50000U) && !pon.lock.held);
  pthread_mutex_destroy(&pon.lock.native);
 }
 puts("Actual SerDes worker: late ITU synchronization completes EPON CSR reset; LOS/missing clocks and all EPON modes preserve their ownership");
}
'''

address_model = r'''
#define ETH_ALEN 6
#define NET_ADDR_SET 3
#define NETDEV_CHANGEADDR 8
struct rtl_oam_port {bool mac_configured;struct rtl9617c_pon *pon;unsigned int llid;bool control;};
struct net_device {struct rtl_oam_port private;u8 address[6];bool locked,netns_immutable;int addr_assign_type;unsigned int updates,notifications,policy_begins,policy_ends;char name[16];const void *netdev_ops,*sysfs_groups[1];unsigned int max_mtu,flags;};
struct device {void *data;};struct device_attribute {};
struct rtl9617c_pon {struct mutex control_lock,lock;bool mpcp_enabled;u8 onu_mac[6],data_mac[6];struct net_device *oam_devices[32],*data_devices[32];void *dev,*ni_dev;};
static bool rtnl;
struct net {unsigned int unused;};
static struct net fabric_net;
static struct net_device *policy_dev;
static bool policy_scope,guard_present=true;
static unsigned int policy_updates,policy_notifications;
static unsigned int live,allocations,frees,fe_attaches;
static bool allocation_fails;
static int fe_attach_error;
#define ASSERT_RTNL() assert(rtnl)
#define rtnl_dereference(p) (assert(rtnl),(p))
#define rcu_dereference(p) (p)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define dev_get_drvdata(dev) ((struct rtl9617c_pon *)(dev)->data)
static void rtnl_lock(void) {assert(!rtnl);rtnl=true;}
static void rtnl_unlock(void) {assert(rtnl);rtnl=false;}
static void *netdev_priv(struct net_device *dev) {return &dev->private;}
static void netdev_lock(struct net_device *dev) {assert(rtnl&&!dev->locked);dev->locked=true;}
static void netdev_unlock(struct net_device *dev) {assert(dev->locked);dev->locked=false;}
static struct net *rtl9617c_switch_policy_begin(struct net_device *dev) {
 assert(rtnl && dev->locked && !policy_scope);
 policy_scope=true;policy_dev=dev;policy_updates=dev->updates;
 policy_notifications=dev->notifications;dev->policy_begins++;
 return guard_present?&fabric_net:NULL;
}
static void rtl9617c_switch_policy_end(struct net *net) {
 assert(policy_scope && policy_dev->locked && rtnl);
 assert(net==(guard_present?&fabric_net:NULL));
 assert(policy_dev->updates==policy_updates+1);
 assert(policy_dev->notifications==policy_notifications+1);
 policy_dev->policy_ends++;policy_dev=NULL;policy_scope=false;
}
static void ether_addr_copy(u8 *dst,const u8 *src) {memcpy(dst,src,6);}
static void eth_addr_add(u8 *mac,long offset) {
 for(int i=5;i>=0 && offset;i--){offset+=mac[i];mac[i]=offset;offset>>=8;}
}
static void eth_hw_addr_set(struct net_device *dev,const u8 *mac) {memcpy(dev->address,mac,6);dev->updates++;}
static int eth_mac_addr(struct net_device *dev,void *address) {
 if(!address)return -EINVAL;
 eth_hw_addr_set(dev,address);return 0;
}
static void call_netdevice_notifiers(int event,struct net_device *dev) {
 assert(rtnl&&dev->locked&&event==NETDEV_CHANGEADDR);
 /* BEGIN must precede the actual address write, and END must follow all
  * notifications. A later CHANGEADDR callback alone cannot provide this. */
 assert(policy_scope && policy_dev==dev && dev->updates==policy_updates+1);
 assert(dev->addr_assign_type==NET_ADDR_SET);
 dev->notifications++;
}
static int mac_pton(const char *text,u8 *out) {unsigned int b[6];if(sscanf(text,"%x:%x:%x:%x:%x:%x",b,b+1,b+2,b+3,b+4,b+5)!=6)return 0;for(unsigned int i=0;i<6;i++)out[i]=b[i];return 1;}
static int is_valid_ether_addr(const u8 *mac) {return !(mac[0]&1)&&memcmp(mac,"\0\0\0\0\0\0",6);}
#define ETH_DATA_LEN 1500
#define IFF_NOARP 0x80
#define SET_NETDEV_DEV(dev,parent) ((void)(parent))
static const int rtl_oam_ops,rtl_data_ops,rtl_oam_group;
static struct net_device *alloc_etherdev(unsigned int size){
 (void)size;if(allocation_fails)return NULL;
 struct net_device *dev=calloc(1,sizeof(*dev));assert(dev);live++;allocations++;return dev;
}
static void free_netdev(struct net_device *dev){assert(live);live--;frees++;free(dev);}
static void netif_carrier_off(struct net_device *dev){(void)dev;}
static int rtl9617c_ni_fe_add_port(void *engine,struct net_device *dev,unsigned int index){
 (void)engine;assert(index<32 && dev->netns_immutable);fe_attaches++;return fe_attach_error;
}

'''
address_test = r'''
int main(void) {
    struct rtl9617c_pon pon={};struct device device={&pon};struct net_device ports[3]={},data[3]={};
    pon.oam_devices[0]=ports;pon.oam_devices[7]=ports+1;pon.oam_devices[31]=ports+2;
    pon.data_devices[0]=data;pon.data_devices[7]=data+1;pon.data_devices[31]=data+2;
    pthread_mutex_init(&pon.lock.native,NULL);pthread_mutex_init(&pon.control_lock.native,NULL);
    struct net_device *initial=rtl_oam_allocate(&pon,0,false);
    assert(initial && initial->netns_immutable && !memcmp(initial->address,"\0\0\0\0\0\0",6));
    free_netdev(initial);
    const char *factory="00:11:22:33:44:ff";
    assert(data_mac_store(&device,NULL,factory,17)==17);
    const u8 expected[3][6]={{0,0x11,0x22,0x33,0x44,0xff},
                           {0,0x11,0x22,0x33,0x45,6},
                           {0,0x11,0x22,0x33,0x45,0x1e}};
    for(unsigned int i=0;i<3;i++) {
        assert(!memcmp(data[i].address,expected[i],6));
        assert(data[i].updates==1 && data[i].notifications==1 && !data[i].locked);
        assert(data[i].policy_begins==1 && data[i].policy_ends==1);
        assert(ports[i].updates==0);
    }
    struct net_device *late=rtl_oam_allocate(&pon,31,false);
    assert(late && late->netns_immutable && !memcmp(late->address,expected[2],6));
    free_netdev(late);
    assert(onu_mac_store(&device,NULL,"02:11:22:33:44:f0",17)==17);
    const u8 oam[3][6]={{2,0x11,0x22,0x33,0x44,0xf0},
                      {2,0x11,0x22,0x33,0x44,0xf7},
                      {2,0x11,0x22,0x33,0x45,0x0f}};
    for(unsigned int i=0;i<3;i++) {
        assert(!memcmp(ports[i].address,oam[i],6));
        assert(!memcmp(data[i].address,expected[i],6) && data[i].updates==1);
    }
    const u8 configured[6]={2,0x55,0x44,0x33,0x22,0x11};
    rtnl_lock();netdev_lock(data+1);
    assert(rtl_data_set_address(data+1,NULL)==-EINVAL && !data[1].private.mac_configured);
    assert(rtl_data_set_address(data+1,(void *)configured)==0 && data[1].private.mac_configured);
    netdev_unlock(data+1);rtnl_unlock();
    assert(data_mac_store(&device,NULL,factory,17)==17);
    assert(!memcmp(data[1].address,configured,6));
    assert(data_mac_store(&device,NULL,"00:00:00:00:00:00",17)==-EINVAL);
    pon.mpcp_enabled=true;
    assert(data_mac_store(&device,NULL,factory,17)==17);
    assert(onu_mac_store(&device,NULL,"02:11:22:33:44:01",17)==-EBUSY);
    /* With no related fabric owner (e.g. an OAM-only endpoint before FE
     * registration), the NULL scope remains balanced and notifications
     * still publish normally. */
    guard_present=false;
    assert(data_mac_store(&device,NULL,"00:11:22:33:44:01",17)==17);
    guard_present=true;
    for(unsigned int i=0;i<3;i++) {
        assert(data[i].policy_begins==data[i].policy_ends);
        assert(ports[i].policy_begins==ports[i].policy_ends);
    }
    /* Every LLID and both data/control roles belong to the same physical
     * namespace. Verify this before FE attachment and on returned devices,
     * plus the real allocator's failure unwind. */
    unsigned int attaches_before=fe_attaches;
    for(unsigned int control=0;control<2;control++)for(unsigned int i=0;i<32;i++) {
        struct net_device *dev=rtl_oam_allocate(&pon,i,control);
        assert(dev && dev->netns_immutable);
        assert(dev->private.pon==&pon && dev->private.llid==i);
        assert(dev->private.control==!!control);
        free_netdev(dev);
    }
    assert(fe_attaches==attaches_before+32 && !live);
    allocation_fails=true;
    assert(!rtl_oam_allocate(&pon,0,false) && !rtl_oam_allocate(&pon,0,true));
    assert(fe_attaches==attaches_before+32 && !live);
    allocation_fails=false;fe_attach_error=-EIO;
    for(unsigned int i=0;i<32;i++) {
        assert(!rtl_oam_allocate(&pon,i,false) && !live);
        struct net_device *dev=rtl_oam_allocate(&pon,i,true);
        assert(dev && dev->netns_immutable);free_netdev(dev);
    }
    assert(fe_attaches==attaches_before+64 && !live && allocations==frees);
    assert(!rtnl&&!pon.lock.held&&!pon.control_lock.held&&!policy_scope);
    pthread_mutex_destroy(&pon.lock.native);pthread_mutex_destroy(&pon.control_lock.native);
    puts("Factory PON Ethernet MAC: pre-publication guard/NULL scope, overrides and locked notifications; all 32 data/control LLIDs namespace-immutable with exact allocator unwind passed");
}
'''

epon_model = r'''
#define MAX_JIFFY_OFFSET (~0UL>>1)
#define time_before(a,b) ((long)((a)-(b))<0)
#define min(a,b) ((a)<(b)?(a):(b))
#define system_wq NULL
#define dev_err_ratelimited(...) ((void)0)
static bool offline_timeout;
static bool llid_timeout,pdc_policy_required;
static bool llid_active;
static u32 llid_preflight_status;
static unsigned int llid_writes;
static bool pdc_failure,pdc_active;
static unsigned int pdc_calls;
static int cleanup_failure;
static unsigned int removals,registration_events;
static void cancel_delayed_work(struct delayed_work *work) {work->pending=false;}
static void mod_delayed_work(void *unused,struct delayed_work *work,unsigned long delay)
{(void)unused;(void)delay;work->pending=true;}
static bool netif_carrier_ok(struct net_device *dev) {return dev->carrier;}
static void netif_carrier_on(struct net_device *dev) {
    if(policy_tracking && !dev->control && !dev->carrier)assert(policy_depth);
    dev->carrier=true;
}
static void netif_carrier_off(struct net_device *dev) {
    if(policy_tracking && !dev->control && dev->carrier)assert(policy_depth);
    dev->carrier=false;
}
static int rtl9617c_ni_fe_cpu_path(void *dev) {(void)dev;assert(0);return -EIO;}
struct device {void *data;};
struct device_attribute {};
static void *dev_get_drvdata(struct device *dev) {return dev->data;}
static int rtl_mpcp_remove_mac(struct rtl9617c_pon *pon,unsigned int index) {
    (void)index;assert(pon->lock.held && !rcu_depth);
    if(policy_tracking)assert(policy_depth);
    removals++;return cleanup_failure;
}
static void rtl_mpcp_registration_event(struct rtl9617c_pon *pon,u32 registered) {
    assert(pon->lock.held && registered!=pon->registered);
    if(policy_tracking)assert(policy_depth);
    registration_events++;
}
static void check_epon_write(u32 value,void *p) {
    if(p==current->mac+PDC_ACCESS) {pdc_calls++;pdc_active=true;}
    if(p==current->mac+PDC_ACCESS || p==current->mac+PDC_DATA0 || p==current->mac+PDC_DATA1)
        if(pdc_policy_required)assert(policy_depth);
    if(p==current->mac+LLID_DATA || p==current->mac+LLID_ACCESS)llid_writes++;
    if(p==current->mac+LLID_ACCESS)llid_active=true;
    if(p==current->mac+OFFLINE || p==current->mac+MPCP_START ||
       p==current->mac+MAC_HIGH || p==current->mac+MAC_LOW ||
       p==current->mac+0x14c0 || p==current->mac+LLID_DATA ||
       p==current->mac+LLID_ACCESS) {
        assert(!rcu_depth);
        if(policy_tracking)assert(policy_depth);
    }
    if(p==current->mac+OFFLINE && !offline_timeout) {
        u32 registered=readl(current->mac+REGISTER_STATUS)&~value;
        memcpy(current->mac+REGISTER_STATUS,&registered,4);
    }
}
static u32 epon_read_hook(const void *p,u32 value) {
    if(p==current->mac+PDC_ACCESS) {
        if(pdc_failure && pdc_active)return BIT(31);
        pdc_active=false;return 0;
    }
    if(p==current->mac+LLID_ACCESS) {
        if(llid_preflight_status)return llid_preflight_status;
        if(llid_timeout && llid_active)return 1;
        if(llid_active) {
            u32 result,command;
            memcpy(&result,current->mac+LLID_RESULT,4);
            memcpy(&command,current->mac+LLID_DATA,4);
            bool add=command&BIT(23);
            if((add && (result==6 || result==7)) || (!add && result==5)) {
                unsigned int index=(command>>16)&63;
                u32 entry=add?command:0;
                memcpy(current->mac+PDC_EPON_LLID_TABLE+index*4,&entry,4);
            }
        }
        llid_active=false;return 0;
    }
    return value;
}
static void check_epon_policy_end(void) {
    /* A worker can run immediately after the last END. Do not allow a
     * still-carrier-up endpoint with a PDC identity from before the LLID
     * command to become eligible at that boundary. */
    if(!current->pdc_configured || !current->data_devices[0] ||
       !current->data_devices[0]->carrier)return;
    for(unsigned int i=0;i<64;i++) {
        u32 entry;memcpy(&entry,current->mac+PDC_EPON_LLID_TABLE+i*4,4);
        assert(current->pdc_source[i]==rtl_pon_data_source(i,entry));
    }
}
'''

epon_test = r'''
int main(void) {
    u32 mac[0xc000/4]={},top[2]={};
    struct net_device data={.carrier=true},second={.carrier=true},control={.carrier=true,.control=true};
    struct rtl9617c_pon pon={.mode=RTL_PON_EPON_D10G,.mac=mac,.top_irq=top,
        .llid_count=1,.registered=1,.mac_prepared=true,.mpcp_enabled=true,
        .traffic_enabled=true,.puc_configured=true,.pdc_configured=true,
        .onu_mac={2,1,2,3,4,5}};
    unsigned int begins;
    current=&pon;starter=pthread_self();
    pthread_mutex_init(&pon.lock.native,NULL);pthread_mutex_init(&pon.control_lock.native,NULL);
    pon.data_devices[0]=&data;pon.oam_devices[0]=&control;
    mac[REGISTER_STATUS/4]=1;mac[0x10/4]=BIT(1);
    policy_tracking=true;write_check=check_epon_write;read_hook=epon_read_hook;
    policy_end_check=check_epon_policy_end;
    for(unsigned int i=0;i<64;i++)pon.pdc_source[i]=rtl_pon_data_source(i,0);
    mutex_lock(&pon.lock);
    /* Teardown may retire LLID0 first; another owned LLID still fences the fabric. */
    struct net *scope=NULL;
    pon.data_devices[0]=NULL;pon.data_devices[1]=&second;
    rtl_pon_policy_begin(&pon,&scope);assert(scope && policy_depth==1 && !rcu_depth);
    rtl9617c_switch_policy_end(scope);
    pon.data_devices[0]=&data;pon.data_devices[1]=NULL;
    /* Normal status reads and ACK events cannot invalidate working flows. */
    begins=policy_begins;rtl_mpcp_refresh(&pon);
    assert(policy_begins==begins && !policy_depth && data.carrier);
    mac[MPCP_IRQ/4]=BIT(1);mac[RTL_MPCP_PACKET_FLAG/4]=3U<<16;
    rtl_mpcp_refresh(&pon);
    assert(policy_begins==begins && !policy_depth && data.carrier);
    mac[MPCP_IRQ/4]=0;
    /* Registration loss: gate before table/key cleanup, event and carrier. */
    mac[REGISTER_STATUS/4]=0;pon.epon_crypto_llids=1;
    rtl_mpcp_refresh(&pon);
    assert(policy_begins>begins && !policy_depth && !data.carrier &&
           !pon.registered && !pon.epon_crypto_llids && removals==1 && registration_events==1);
    begins=policy_begins;rtl_mpcp_refresh(&pon);assert(policy_begins==begins);
    mac[REGISTER_STATUS/4]=1;rtl_mpcp_refresh(&pon);
    assert(policy_begins>begins && !policy_depth && data.carrier && pon.registered==1 && registration_events==2);
    /* Holdover itself preserves service; only actual expiry fences the offline write. */
    mac[0x10/4]=0;pon.epon_holdover_enabled=1;pon.epon_holdover_ms[0]=200;jiffies=100;
    begins=policy_begins;rtl_mpcp_refresh(&pon);
    assert(policy_begins==begins && pon.epon_holdover_active==1 && data.carrier);
    jiffies=301;rtl_mpcp_refresh(&pon);
    assert(policy_begins>begins && !policy_depth && !data.carrier && !pon.registered && removals==2);
    /* A failed offline command still closes before publication and balances scope. */
    pon.registered=1;mac[REGISTER_STATUS/4]=1;data.carrier=true;
    pon.epon_holdover_pending=1;pon.epon_holdover_start[0]=100;offline_timeout=true;
    begins=policy_begins;rtl_mpcp_refresh(&pon);
    assert(policy_begins>begins && !policy_depth && !data.carrier &&
           pon.registered==1 && pon.epon_holdover_error==-ETIMEDOUT);
    offline_timeout=false;mac[0x10/4]=BIT(1);rtl_mpcp_refresh(&pon);assert(data.carrier);
    /* Backoff samples PKT_FLAG once and gates the actual NACK-only write. */
    mac[MPCP_IRQ/4]=BIT(1);mac[RTL_MPCP_PACKET_FLAG/4]=4U<<16;
    begins=policy_begins;rtl_mpcp_refresh(&pon);
    assert(policy_begins>begins && !policy_depth && pon.backoff.active && data.carrier);
    mac[MPCP_IRQ/4]=0;
    pon.epon_llid_cleanup=1;cleanup_failure=-EIO;
    begins=policy_begins;rtl_mpcp_refresh(&pon);
    assert(policy_begins>begins && !policy_depth && pon.epon_llid_cleanup==1 &&
           pon.epon_llid_cleanup_error==-EIO);
    cleanup_failure=0;rtl_mpcp_refresh(&pon);assert(!pon.epon_llid_cleanup && !policy_depth);
    /* Gate-timeout RX crypto reset is a real mutation even without a registration delta. */
    pon.epon_crypto_llids=1;mac[MPCP_IRQ/4]=BIT(3);
    begins=policy_begins;rtl_mpcp_refresh(&pon);assert(policy_begins>begins && !policy_depth);
    mac[MPCP_IRQ/4]=0;
    /* Traffic-control caller shares the actual carrier helper, no IRQ required. */
    pon.data_devices[1]=&second;pon.registered=3;pon.traffic_enabled=false;
    begins=policy_begins;rtl_pon_oam_carrier(&pon);
    assert(policy_begins==begins+1 && !policy_depth && !data.carrier && !second.carrier);
    begins=policy_begins;rtl_pon_oam_carrier(&pon);assert(policy_begins==begins);
    pon.data_devices[1]=NULL;pon.registered=1;pon.traffic_enabled=true;
    rtl_pon_oam_carrier(&pon);assert(data.carrier);
    /* A fabric absent at early init has a valid NULL scope and no false ownership. */
    guard_present=false;policy_tracking=false;pon.traffic_enabled=false;
    begins=policy_begins;rtl_pon_oam_carrier(&pon);
    assert(policy_begins==begins && !policy_depth && !data.carrier);
    guard_present=true;policy_tracking=true;
    mutex_unlock(&pon.lock);
    /* Actual stop/configure covers identity publication and every error/early return. */
    mutex_lock(&pon.control_lock);
    begins=policy_begins;assert(!rtl_pon_mpcp_stop_locked(&pon));
    assert(policy_begins>begins && !policy_depth && !pon.mpcp_enabled && !data.carrier);
    begins=policy_begins;assert(!rtl_pon_mpcp_configure_locked(&pon));
    assert(policy_begins>begins && !policy_depth && pon.mpcp_enabled);
    begins=policy_begins;assert(!rtl_pon_mpcp_configure_locked(&pon));
    assert(policy_begins==begins && !policy_depth);
    pon.mpcp_enabled=false;pon.mac_prepared=false;
    assert(rtl_pon_mpcp_configure_locked(&pon)==-EAGAIN && !policy_depth && policy_begins==begins);
    pon.mode=RTL_PON_GPON;
    assert(rtl_pon_mpcp_configure_locked(&pon)==-EOPNOTSUPP && !policy_depth && policy_begins==begins);
    mutex_unlock(&pon.control_lock);
    /* The direct sysfs LLID path shares the gate through the PDC refresh. */
    struct device device={.data=&pon};
    const char add[]="add 3 0 1234 0",del[]="delete 3 0 1234 0";
    pon.mode=RTL_PON_EPON_D10G;pon.mac_prepared=true;pon.mpcp_enabled=true;pon.registered=1;
    pon.traffic_enabled=true;pon.pdc_configured=true;data.carrier=true;
    mac[REGISTER_STATUS/4]=1;pdc_policy_required=true;
    mac[LLID_RESULT/4]=6;begins=policy_begins;
    assert(llid_table_store(&device,NULL,add,sizeof(add)-1)==sizeof(add)-1);
    assert(policy_begins==begins+2 && !policy_depth && !pon.lock.held && !pon.control_lock.held);
    mac[LLID_RESULT/4]=5;
    assert(llid_table_store(&device,NULL,del,sizeof(del)-1)==sizeof(del)-1 && !policy_depth);
    const int errors[]={-ENOSPC,-ENOENT,-EIO};
    const u32 statuses[]={1,2,0};
    for(unsigned int i=0;i<3;i++) {
        unsigned int before_pdc=pdc_calls;mac[LLID_RESULT/4]=statuses[i];
        assert(llid_table_store(&device,NULL,add,sizeof(add)-1)==errors[i]);
        assert(!policy_depth && pdc_calls==before_pdc && !pon.lock.held && !pon.control_lock.held);
        if(i<2)assert(pon.pdc_configured && data.carrier);
        else assert(!pon.pdc_configured && !data.carrier && pon.pdc_error==-EIO);
    }
    /* A complete reconstruction, not an idle poll, is the recovery barrier. */
    mutex_lock(&pon.control_lock);assert(!rtl_pon_pdc_configure_locked(&pon));mutex_unlock(&pon.control_lock);
    assert(pon.pdc_configured && data.carrier && control.carrier && !policy_depth);
    llid_timeout=true;
    assert(llid_table_store(&device,NULL,add,sizeof(add)-1)==-ETIMEDOUT && !policy_depth);
    assert(!pon.pdc_configured && !data.carrier && control.carrier && pon.pdc_error==-ETIMEDOUT);
    mutex_lock(&pon.lock);rtl_mpcp_refresh(&pon);mutex_unlock(&pon.lock);
    assert(!pon.pdc_configured && !data.carrier && !policy_depth);
    unsigned int before_pdc=pdc_calls;
    mutex_lock(&pon.control_lock);assert(rtl_pon_pdc_configure_locked(&pon)==-EBUSY);mutex_unlock(&pon.control_lock);
    assert(!pon.pdc_configured && !data.carrier && pdc_calls==before_pdc && !policy_depth);
    unsigned int writes=llid_writes;
    assert(llid_table_store(&device,NULL,add,sizeof(add)-1)==-EBUSY && !policy_depth && llid_writes==writes);
    llid_preflight_status=~0U;
    assert(llid_table_store(&device,NULL,add,sizeof(add)-1)==-EIO && !policy_depth && llid_writes==writes);
    llid_preflight_status=0;llid_active=false;llid_timeout=false;
    mac[LLID_RESULT/4]=~0U;
    assert(llid_table_store(&device,NULL,add,sizeof(add)-1)==-EIO && !policy_depth);
    /* Late LLID completion and another successful LLID edit cannot alone
     * reauthorize an old PDC mapping or carrier. */
    mac[LLID_RESULT/4]=7;
    assert(llid_table_store(&device,NULL,add,sizeof(add)-1)==sizeof(add)-1 && !policy_depth);
    assert(!pon.pdc_configured && !data.carrier);
    mutex_lock(&pon.control_lock);assert(!rtl_pon_pdc_configure_locked(&pon));mutex_unlock(&pon.control_lock);
    assert(pon.pdc_configured && data.carrier && !policy_depth);
    /* A later PDC refresh timeout has the same persistent carrier barrier. */
    const char remap[]="add 3 4 1234 0";
    llid_timeout=false;mac[LLID_RESULT/4]=7;pdc_failure=true;
    assert(llid_table_store(&device,NULL,remap,sizeof(remap)-1)==-ETIMEDOUT && !policy_depth);
    assert(!pon.pdc_configured && !data.carrier && control.carrier);
    pdc_failure=0;begins=policy_begins;pon.mode=RTL_PON_GPON;
    assert(llid_table_store(&device,NULL,add,sizeof(add)-1)==-EOPNOTSUPP && !policy_depth && policy_begins==begins);
    assert(llid_table_store(&device,NULL,"bad",3)==-EINVAL && !policy_depth && policy_begins==begins);
    assert(policy_begins==policy_ends && !rcu_depth && !policy_depth);
    pthread_mutex_destroy(&pon.lock.native);pthread_mutex_destroy(&pon.control_lock.native);
    puts("Actual EPON control: registration/carrier/holdover/NACK/reset/stop/configure/sysfs-LLID pre-publication gates, no-change ACK/polls, NULL owner and timeout/cleanup unwind passed");
}
'''

controller = read('rtl9617c-pon.c')
serdes = read('rtl9617c-pon-serdes.c')
timing_show = function(controller, 'serdes_timing_show')
assert 'mutex_trylock(&pon->lock)' in timing_show
assert 'reason=busy retryable=1' in timing_show
assert 'rtl_pon_serdes_timing(pon, buf)' in timing_show
assert 'mutex_unlock(&pon->lock)' in timing_show
assert 'readl(' not in timing_show
assert 'static DEVICE_ATTR_RO(serdes_timing)' in controller
assert '&dev_attr_serdes_timing.attr' in controller
assert 'readl(' not in function(serdes, 'rtl_pon_serdes_timing')
mpcp = read('rtl9617c-pon-mpcp.c')
oam = read('rtl9617c-pon-oam.c')
pdc = read('rtl9617c-pon-pdc.c')
records = []
(root / 'artifacts').mkdir(exist_ok=True)
(root / 'logs').mkdir(exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='control-tests-', dir=root / 'artifacts') as directory:
    directory = Path(directory)
    for case in args.case or ['transactions', 'address']:
        if case == 'transactions':
            constants = '\n'.join(re.findall(r'^#define .*$', serdes + '\n' + mpcp, re.M))
            definitions = function(mpcp, 'rtl_pon_llid_mask')
            if 'void rtl_pon_policy_begin' in mpcp:
                definitions += function(mpcp, 'rtl_pon_policy_begin')
            locked = '_locked' if 'rtl_pon_mpcp_stop_locked(' in mpcp else ''
            definitions += function(mpcp, 'rtl_pon_mpcp_stop' + locked) + function(mpcp, 'rtl_pon_mpcp_configure' + locked)
            definitions += function(serdes, 'rtl_pon_serdes_configure' + locked)
            definitions += function(serdes, 'rtl_pon_serdes_timing')
            definitions += function(controller, 'serdes_timing_show')
            if locked:
                if 'int rtl_pon_stop_locked' in controller:
                    definitions += function(controller, 'rtl_pon_stop_locked')
                definitions += function(controller, 'rtl_pon_mpcp_configure') + function(controller, 'rtl_pon_serdes_configure')
            source = common + timing_model + constants + '\n' + definitions + transaction_test
        elif case == 'serdes-sync':
            constants = '\n'.join(re.findall(r'^#define .*$', serdes, re.M))
            source = common + sync_model + constants + '\n' + function(serdes, 'rtl_pon_serdes_work') + sync_test
        elif case == 'epon-policy':
            constants = '\n'.join(re.findall(r'^#define .*$', mpcp + '\n' + pdc, re.M))
            prefix = common.replace('static void rtl_pon_oam_carrier(struct rtl9617c_pon *pon) {assert(pon->lock.held);}',
                                    'static void rtl_pon_oam_carrier(struct rtl9617c_pon *pon);')
            definitions = function(oam, 'rtl_pon_oam_carrier')
            definitions += function(mpcp, 'rtl_pon_llid_mask') + function(mpcp, 'rtl_pon_policy_begin')
            for name in ('rtl_pdc_access', 'rtl_pdc_write', 'rtl_pon_pdc_refresh', 'rtl_pdc_itu_configure',
                         'rtl_pon_pdc_configure_locked'):
                definitions += function(pdc, name)
            definitions += re.search(r'struct rtl_mpcp_policy_io \{[^}]*\};', mpcp).group(0) + '\n'
            for name in ('rtl_mpcp_read', 'rtl_mpcp_write', 'rtl_mpcp_holdover', 'rtl_mpcp_refresh', 'rtl_pon_llid_update',
                         'rtl_pon_mpcp_stop_locked', 'rtl_pon_mpcp_configure_locked'):
                definitions += function(mpcp, name)
            definitions += function(controller, 'llid_table_store')
            source = prefix + constants + '\n' + epon_model + definitions + epon_test
        else:
            if not args.revision:
                assert '.ndo_set_mac_address =' not in oam.split('static const struct net_device_ops rtl_oam_ops = {')[1].split('};',1)[0]
            # Reuse the host mutex primitive; the RX/MMIO model is unnecessary.
            prefix = common[:common.index('struct delayed_work')]
            helper = function(oam, 'rtl_data_set_address') + function(oam, 'rtl_port_address') if 'static void rtl_port_address' in oam else ''
            source = prefix + address_model + helper + function(oam, 'rtl_pon_oam_address') + function(oam, 'rtl_pon_data_address') + function(controller, 'onu_mac_store') + function(controller, 'data_mac_store') + function(oam, 'rtl_oam_allocate') + address_test
        variants = [('production', source)]
        if args.mutants and case == 'address':
            mutations = {
                'mutable_data_namespace': ('dev->netns_immutable = true;',
                                           'dev->netns_immutable = control;'),
                'mutable_control_namespace': ('dev->netns_immutable = true;',
                                              'dev->netns_immutable = !control;'),
                'gate_after_address_publication': (
                    'policy = rtl9617c_switch_policy_begin(dev);\n\teth_hw_addr_set(dev, mac);',
                    'eth_hw_addr_set(dev, mac);\n\tpolicy = rtl9617c_switch_policy_begin(dev);'),
                'end_before_address_notification': (
                    'call_netdevice_notifiers(NETDEV_CHANGEADDR, dev);\n\trtl9617c_switch_policy_end(policy);',
                    'rtl9617c_switch_policy_end(policy);\n\tcall_netdevice_notifiers(NETDEV_CHANGEADDR, dev);'),
            }
            for name, (before, after) in mutations.items():
                if source.count(before) != 1:
                    raise SystemExit(f'Nonunique mutation target: {name}')
                variants.append((name, source.replace(before, after, 1)))
        if args.mutants and case == 'epon-policy':
            mutations = {
                'unguarded_carrier': ('policy = rtl9617c_switch_policy_begin(dev);', 'policy = NULL;'),
                'unguarded_registration': ('if (registered != pon->registered || pon->epon_llid_cleanup)', 'if (pon->epon_llid_cleanup)'),
                'holdover_gate_after_offline': (
                    'rtl_pon_policy_begin(pon, policy);\n\t\trtl_pon_update(pon->mac + OFFLINE, BIT(channel), BIT(channel));',
                    'rtl_pon_update(pon->mac + OFFLINE, BIT(channel), BIT(channel));\n\t\trtl_pon_policy_begin(pon, policy);'),
                'backoff_gate_after_write': (
                    'rtl_pon_policy_begin(io->pon, io->policy);\n\twritel(value, io->pon->mac + reg);',
                    'writel(value, io->pon->mac + reg);\n\trtl_pon_policy_begin(io->pon, io->policy);'),
                'unguarded_configure': (
                    'rtl_pon_policy_begin(pon, &policy);\n\tret = rtl_pon_epon_crypto_forget(pon, pon->epon_crypto_llids);',
                    'ret = rtl_pon_epon_crypto_forget(pon, pon->epon_crypto_llids);'),
                'unguarded_stop': (
                    'if (pon->mpcp_enabled || pon->registered)\n\t\trtl_pon_policy_begin(pon, &policy);',
                    'if (false)\n\t\trtl_pon_policy_begin(pon, &policy);'),
                'unguarded_sysfs_llid': (
                    'rtl_pon_policy_begin(pon, &policy);\n\t\tret = rtl_pon_llid_update(pon, add, index, mac, llid, multicast);',
                    'ret = rtl_pon_llid_update(pon, add, index, mac, llid, multicast);'),
                'sysfs_scope_ends_before_pdc': (
                    'if (!ret)\n\t\tret = rtl_pon_pdc_refresh(pon);\n\trtl9617c_switch_policy_end(policy);',
                    'rtl9617c_switch_policy_end(policy);\n\tif (!ret)\n\t\tret = rtl_pon_pdc_refresh(pon);'),
                'overwrite_late_llid_window': (
                    'if (status & BIT(0)) {\n\t\tret = -EBUSY;',
                    'if (false) {\n\t\tret = -EBUSY;'),
                'accept_failed_llid_result': (
                    'status = readl(pon->mac + LLID_RESULT);\n\tif (status == ~0U) {\n\t\tret = -EIO;\n\t\tgoto uncertain;\n\t}',
                    'status = readl(pon->mac + LLID_RESULT);'),
                'timeout_keeps_old_business_mapping': (
                    'pon->pdc_error = ret;\n\tpon->pdc_configured = false;\n\trtl_pon_oam_carrier(pon);\n\treturn ret;',
                    'pon->pdc_error = ret;\n\treturn ret;'),
                'timeout_does_not_publish_carrier_down': (
                    'pon->pdc_error = ret;\n\tpon->pdc_configured = false;\n\trtl_pon_oam_carrier(pon);\n\treturn ret;',
                    'pon->pdc_error = ret;\n\tpon->pdc_configured = false;\n\treturn ret;'),
            }
            for name, (before, after) in mutations.items():
                if source.count(before) != 1:
                    raise SystemExit(f'Nonunique mutation target: {name}')
                variants.append((name, source.replace(before, after, 1)))
        for variant, program in variants:
            cfile = directory / f'{case}-{variant}.c'
            binary = directory / f'{case}-{variant}'
            cfile.write_text(program)
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter',
                            '-O1', '-g', '-pthread', '-fsanitize=address,undefined', '-I', str(headers), str(cfile), '-o', str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20,
                                    env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0',
                                         'LSAN_OPTIONS': 'detect_leaks=0'})
            if variant == 'production':
                if result.returncode:
                    print(result.stderr,end='')
                    raise SystemExit(result.returncode)
                print(result.stdout,end='')
                records.append({'case':case,'passed':True,'output':result.stdout.strip()})
            else:
                assert result.returncode and 'Assertion' in result.stderr, result
                print(f'PON identity policy mutation rejected: {variant}')
                records.append({'case':case,'mutation':variant,'rejected':True})
if not args.revision:
    (root / 'logs/pon-control-transaction-tests.json').write_text(json.dumps({'tests':records,
        'production_source_sha256':{name:hashlib.sha256(read(name).encode()).hexdigest() for name in (
            'rtl9617c-pon.c','rtl9617c-pon-serdes.c','rtl9617c-pon-mpcp.c','rtl9617c-pon-oam.c','rtl9617c-pon-pdc.c')},
        'sanitizers':['ASan','UBSan'],'hardware_access':False},indent=2)+'\n')
