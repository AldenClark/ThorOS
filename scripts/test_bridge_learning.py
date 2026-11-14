#!/usr/bin/env python3
"""Keep the retired packet-observation learner disabled; retain its counterexample.

The old learner is test-only: its positive paths are NOT production offload
coverage. The retired compatibility header is compiled separately below and
must register no packet hooks or work. Native switchdev has independent L2
policy/transaction/lifecycle tests; passing this legacy fixture is NOT native
switch coverage. scripts/test_fe_evto.py reuses the historical fixture to
exercise the production EVTO compiler.
"""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
production = (drivers / 'rtl9617c-fe-bridge.h').read_text()
source = (root / 'scripts/fixtures/rtl9617c-bridge-legacy-model.h').read_text()
fe = (drivers / 'rtl9617c-fe.c').read_text()

def function(name):
    match = re.search(r'^static [^\n]*\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    start = match.start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

common = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
typedef uint8_t u8;typedef uint16_t u16,__be16;typedef uint32_t u32;typedef uint64_t u64;
#include "rtl9617c-fe-format.h"
#include "rtl9617c-pon-path.h"
#include "linux/rtl9617c-bridge.h"
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_PPP_SES 0x8864
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define PPP_IP 0x21
#define PPP_IPV6 0x57
#define VLAN_VID_MASK 4095
#define VLAN_CFI_MASK 4096
#define VLAN_PRIO_SHIFT 13
#define VLAN_HLEN 4
#define BR_STATE_FORWARDING 3
#define NF_ACCEPT 1
#define SKB_EXT_RTL9617C_BRIDGE 0
#define FE_BRIDGE_PENDING 256
#define HZ 100
#define system_wq 0
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v,n) ((v)=(n))
#define time_after(a,b) ((long)((b)-(a))<0)
#define time_after_eq(a,b) ((long)((a)-(b))>=0)
struct list_head {struct list_head *next,*prev;};
struct rb_node {unsigned int indexed;};
struct rb_root {unsigned int count;};
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(struct list_head *c=(h)->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m));c=c->next)
#define list_for_each_entry_safe(p,n,h,m) for(struct list_head *c=(h)->next,*nc=c->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m),(n)=container_of(nc,__typeof__(*(n)),m),1);c=nc,nc=c->next)
#define list_last_entry(h,t,m) container_of((h)->prev,t,m)
static void init_list(struct list_head *h){h->next=h->prev=h;}
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
struct net {unsigned int references;};
struct net_device {unsigned int ifindex,state;bool running,carrier,bridge,filtering;u16 vlan,protocol,pvid,qos;struct net_device *master,*lower;struct net *net;};
struct sk_buff {u8 frame[96];unsigned int len,priority;u16 vlan,vlan_proto;bool tagged,gso,extension;struct rtl9617c_bridge_frame saved;};
struct ethhdr {u8 h_dest[6],h_source[6];__be16 h_proto;} __attribute__((packed));
struct vlan_hdr {__be16 h_vlan_TCI,h_vlan_encapsulated_proto;};
struct nf_hook_state {struct net *net;struct net_device *in,*out;};
struct rtl_fe;
struct rtl_fe_port {struct net_device *netdev;unsigned int source,destination,llid;bool retired;};
struct work_struct {int unused;};struct delayed_work {struct work_struct work;unsigned int queued;};
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
struct rtl_dq_io {int unused;};
struct rtl_fe {struct list_head flows;struct rb_root cookies;struct rtl_fe_port *ports[2];struct net_device *itu_netdev;struct rtl_itu_paths *itu_paths;unsigned char ppp_protocol_ids[2];bool enabled;int lock;};
struct fe_bridge_packet {struct net *net;struct rtl9617c_bridge_frame input,output;unsigned int bridge,ingress,egress;u16 vid;};
struct rtl_fe_bridge {struct rtl_fe *fe;struct delayed_work work;int pending_lock;unsigned int read,write;int epoch,flush,recheck;unsigned long next_maintenance;bool active;u32 queued,coalesced,overflow,work_runs,maintenance_runs;bool stopping;struct fe_bridge_packet pending[256];};
static struct net_device *devices[128],*fdb_source,*fdb_destination;
static unsigned int installed,deleted,refreshed,age=2;
static bool fail_age_read;
static unsigned long jiffies=100;
static int atomic_read(int *v){return *v;}
static int atomic_xchg(int *v,int n){int old=*v;*v=n;return old;}
static bool rtl_fe_enabled(struct rtl_fe *f){return f->enabled;}
static bool skb_is_gso(struct sk_buff *s){return s->gso;}
static bool is_vlan_dev(struct net_device *d){return d->lower!=NULL;}
static u16 vlan_dev_vlan_id(struct net_device *d){return d->vlan;}
static __be16 vlan_dev_vlan_proto(struct net_device *d){return htons(d->protocol);}
static u16 vlan_dev_get_egress_qos_mask(struct net_device *d,u32 priority){(void)priority;return d->qos;}
static struct net_device *vlan_dev_real_dev(struct net_device *d){return d->lower;}
static void ether_addr_copy(u8 *d,const u8 *s){memcpy(d,s,6);}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static bool is_valid_ether_addr(const u8 *a){return !(a[0]&1) && memcmp(a,"\0\0\0\0\0\0",6);}
static struct ethhdr *eth_hdr(struct sk_buff *s){return (void *)s->frame;}
static bool eth_type_vlan(__be16 p){return p==htons(0x8100)||p==htons(0x88a8);}
static bool skb_vlan_tag_present(struct sk_buff *s){return s->tagged;}
static u16 skb_vlan_tag_get(struct sk_buff *s){return s->vlan;}
static void *skb_header_pointer(struct sk_buff *s,unsigned int offset,unsigned int length,void *storage){(void)storage;return offset+14+length<=s->len?s->frame+14+offset:NULL;}
static u16 get_unaligned_be16(const void *p){const u8 *v=p;return v[0]*256+v[1];}
static void *skb_ext_add(struct sk_buff *s,int id){(void)id;s->extension=true;return &s->saved;}
static const void *skb_ext_find(struct sk_buff *s,int id){(void)id;return s->extension?&s->saved:NULL;}
static struct net_device *netdev_master_upper_dev_get_rcu(struct net_device *d){return d->master;}
static struct net_device *netdev_master_upper_dev_get(struct net_device *d){return d->master;}
static bool netif_is_bridge_master(struct net_device *d){return d->bridge;}
static bool br_vlan_enabled(struct net_device *d){return d->filtering;}
static int br_vlan_get_proto(struct net_device *d,u16 *p){*p=d->protocol;return 0;}
static int br_vlan_get_pvid_rcu(struct net_device *d,u16 *p){*p=d->pvid;return 0;}
static void spin_lock_bh(int *v){assert(!*v);*v=1;}
static void spin_unlock_bh(int *v){assert(*v);*v=0;}
static void get_net(struct net *n){n->references++;}
static void (*after_put_net)(void);
static void put_net(struct net *n){assert(n->references);n->references--;if(after_put_net)after_put_net();}
static void mod_delayed_work(int q,struct delayed_work *w,unsigned int t){(void)q;(void)t;w->queued++;}
static void queue_delayed_work(int q,struct delayed_work *w,unsigned int t){assert(q==0&&t==HZ);w->queued++;}
static struct net_device *__dev_get_by_index(struct net *n,unsigned int i){(void)n;return i<128?devices[i]:NULL;}
static bool netif_running(struct net_device *d){return d->running;}
static bool netif_carrier_ok(struct net_device *d){return d->carrier;}
static unsigned int br_port_get_stp_state(struct net_device *d){return d->state;}
static struct net_device *br_fdb_find_port(struct net_device *br,const u8 *mac,u16 vid){(void)br;(void)vid;return mac[5]==1?fdb_source:fdb_destination;}
static struct rtl_fe_port *fe_port(struct rtl_fe *fe,struct net_device *d){for(unsigned int i=0;i<2;i++)if(fe->ports[i]->netdev==d && !fe->ports[i]->retired)return fe->ports[i];return NULL;}
static int fe_vlan_tpid(__be16 p){return p==htons(0x8100)?1:p==htons(0x88a8)?2:-EOPNOTSUPP;}
static struct net *dev_net(struct net_device *d){return d->net;}
static unsigned long br_get_ageing_time(struct net_device *d){assert(d&&d->bridge);return 30000;}
static unsigned long clock_t_to_jiffies(unsigned long t){return t;}
static void rtnl_lock(void){}
static void rtnl_unlock(void){}
static void mutex_lock(int *v){assert(!*v);*v=1;}
static void mutex_unlock(int *v){assert(*v);*v=0;}
static void rb_erase(struct rb_node *node,struct rb_root *root){assert(node->indexed&&root->count);node->indexed=0;root->count--;}
struct rtl_fe_flow;
static void fe_index_flow(struct rtl_fe *fe,struct rtl_fe_flow *flow);
static struct rtl_dq_io fe_io(struct rtl_fe *fe){(void)fe;return (struct rtl_dq_io){};}
static int rtl_fe_main_age_read(struct rtl_dq_io *io,unsigned int index,unsigned int *value){(void)io;(void)index;if(fail_age_read)return -EIO;*value=age;return 0;}
static int rtl_fe_main_age(struct rtl_dq_io *io,unsigned int index,unsigned int value){(void)io;(void)index;assert(value==1);return 0;}
static void br_fdb_refresh_offload(struct net_device *d,const u8 *mac,u16 vid,bool source){(void)d;(void)mac;(void)vid;(void)source;refreshed++;}
'''
structs = '\n'.join(re.search(r'struct '+name+r' \{.*?\n\};',fe,re.S)[0] for name in ['rtl_fe_flow','rtl_fe_rule'])
backend = r'''
static struct rtl_fe_rule last;
static int fe_install(struct rtl_fe_port *port,struct rtl_fe_rule data,unsigned long cookie){
 if(!port->netdev->carrier || !data.output->netdev->carrier)return -EAGAIN;
 struct rtl_fe_flow *flow=calloc(1,sizeof(*flow));assert(flow);last=data;installed++;
 flow->input=port;flow->output=data.output;flow->bridge=true;flow->published=true;flow->installed=true;
 flow->cookie=cookie;flow->ethernet_protocol=data.ethernet_protocol;flow->ingress_session=data.pppoe_session;
 memcpy(flow->ethernet_source,data.source,6);memcpy(flow->destination,data.destination,6);
 list_add_tail(&flow->list,&port->fe->flows);fe_index_flow(port->fe,flow);return 0;
}
static void fe_index_flow(struct rtl_fe *fe,struct rtl_fe_flow *flow){assert(!flow->cookie_node.indexed);flow->cookie_node.indexed=1;fe->cookies.count++;}
static int fe_delete(struct rtl_fe *fe,struct rtl_fe_flow *f){rb_erase(&f->cookie_node,&fe->cookies);f->list.prev->next=f->list.next;f->list.next->prev=f->list.prev;free(f);deleted++;return 0;}
static struct rtl_fe_bridge *backlog_bridge;
static struct fe_bridge_packet backlog_packet;
static unsigned backlog_injections;
static void inject_backlog(void){
 if(!backlog_injections)return;
 unsigned next=(backlog_bridge->write+1)%FE_BRIDGE_PENDING;
 assert(next!=backlog_bridge->read);
 get_net(backlog_packet.net);
 backlog_bridge->pending[backlog_bridge->write]=backlog_packet;
 backlog_bridge->write=next;
 backlog_injections--;
}
'''.replace('struct rtl_fe_port {', 'struct rtl_fe_port {')
common = common.replace('struct rtl_fe_port {struct net_device', 'struct rtl_fe_port {struct rtl_fe *fe;struct net_device')
test = r'''
int main(void){
 struct net net={};
 struct net_device br={.ifindex=10,.bridge=true,.protocol=0x8100,.net=&net};
 struct net_device lan={.ifindex=1,.running=true,.carrier=true,.state=3,.master=&br,.net=&net};
 struct net_device pon={.ifindex=7,.running=true,.carrier=true,.state=3,.net=&net};
 struct net_device vlan={.ifindex=70,.running=true,.carrier=true,.state=3,.master=&br,.lower=&pon,.vlan=100,.protocol=0x8100,.qos=4<<13,.net=&net};
 struct net_device other={.ifindex=2,.running=true,.carrier=true,.state=3,.master=&br,.net=&net};
 devices[1]=&lan;devices[2]=&other;devices[7]=&pon;devices[10]=&br;devices[70]=&vlan;
 struct rtl_fe_port lp={.netdev=&lan,.source=0,.destination=0},pp={.netdev=&pon,.source=7,.destination=32};
 struct rtl_fe fe={.ports={&lp,&pp},.ppp_protocol_ids={4,9},.enabled=true};lp.fe=pp.fe=&fe;init_list(&fe.flows);
 struct rtl_fe_bridge bridge={.fe=&fe};
 struct sk_buff skb={.len=60,.priority=4};
 memcpy(skb.frame,"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x88\x64\x11\0\x12\x34\0\x26\0\x21",22);
 struct nf_hook_state wire={.net=&net,.in=&lan},input=wire,output={.net=&net,.out=&vlan};
 fdb_source=&lan;fdb_destination=&vlan;
 assert(fe_bridge_wire(&bridge,&skb,&wire)==NF_ACCEPT);
 /* A routed/local-out packet has no bridge ingress decision. */
 fe_bridge_forwarded(&bridge,&skb,&output);assert(bridge.read==bridge.write);
 assert(fe_bridge_capture(&bridge,&skb,&input)==NF_ACCEPT && skb.saved.port==1);
 fe_bridge_forwarded(&bridge,&skb,&output);assert(net.references==1 && bridge.write==1);
 unsigned queued_work=bridge.work.queued;
 for(unsigned i=0;i<1000;i++)fe_bridge_forwarded(&bridge,&skb,&output);
 assert(net.references==1 && bridge.write==1 && bridge.coalesced==1000);
 assert(bridge.work.queued==queued_work && bridge.overflow==0);
 fe_bridge_work(&bridge.work.work);
 assert(!net.references && installed==1 && last.bridge && last.action.bridge);
 assert(bridge.work_runs==1 && bridge.maintenance_runs==1 && bridge.queued==1);
 assert(last.vlan_count==0 && last.action.vlan_set && last.action.vlan_count==1);
 assert(last.action.vlan[0].vid==100 && last.action.vlan[0].priority==4);
 assert(last.pppoe_session==0x1234 && !last.action.pppoe_pop && !last.egress_pppoe);
 assert(last.key.mask==57 && last.action.destination==32 && last.ppp_protocol_slot==4);
 /* Counterexample: two actual Ethernet/IPv4/TCP frames have the same MACs
  * and differ only in dport 443/22. A bridge policy may accept the former
  * and reject the latter, but the historical production parser and its
  * L2 key discard the very field on which that policy depends. */
 assert(last.key.source_port==0 && last.key.destination_port==0);
 struct sk_buff allowed={.len=54},denied;
 struct rtl9617c_bridge_frame allowed_frame={},denied_frame={};
 memcpy(allowed.frame,skb.frame,12);
 allowed.frame[12]=0x08;allowed.frame[13]=0x00;
 allowed.frame[14]=0x45;allowed.frame[23]=6;
 allowed.frame[36]=1;allowed.frame[37]=0xbb;
 denied=allowed;denied.frame[36]=0;denied.frame[37]=22;
 assert(get_unaligned_be16(allowed.frame+36)==443);
 assert(get_unaligned_be16(denied.frame+36)!=443);
 assert(!fe_bridge_frame(&allowed,&allowed_frame));
 assert(!fe_bridge_frame(&denied,&denied_frame));
 assert(!memcmp(&allowed_frame,&denied_frame,sizeof(allowed_frame)));
 unsigned int https[RTL_FE_KEY_WORDS],ssh[RTL_FE_KEY_WORDS];
 rtl_fe_bridge_key(https,allowed_frame.source,allowed_frame.destination,
                   allowed_frame.protocol,0,0,59);
 rtl_fe_bridge_key(ssh,denied_frame.source,denied_frame.destination,
                   denied_frame.protocol,0,0,59);
 assert(!memcmp(https,ssh,sizeof(https)));
 /* Age-read MMIO can fail transiently. The next maintenance must remain armed. */
 fail_age_read=true;jiffies+=HZ;fe_bridge_work(&bridge.work.work);
 assert(bridge.active && bridge.work.queued>=3 && deleted==0);
 fail_age_read=false;
 jiffies+=HZ;fe_bridge_work(&bridge.work.work);assert(refreshed==2 && deleted==0);
 /* Destination movement removes the old rule before another frame is learned. */
 fdb_destination=&other;bridge.recheck=1;fe_bridge_work(&bridge.work.work);assert(deleted==1);
 assert(fe.flows.next==&fe.flows);
 /* Keep adding an invalid flow observation while work consumes its 256-entry
  * budget. No active flow remains to arm periodic maintenance, so the worker
  * MUST explicitly reschedule the residual queue. */
 backlog_bridge=&bridge;backlog_packet=bridge.pending[0];backlog_injections=300;
 assert(bridge.read==bridge.write);get_net(backlog_packet.net);
 bridge.pending[bridge.write]=backlog_packet;
 bridge.write=(bridge.write+1)%FE_BRIDGE_PENDING;
 after_put_net=inject_backlog;
 queued_work=bridge.work.queued;
 fe_bridge_work(&bridge.work.work);
 assert(bridge.read!=bridge.write && bridge.work.queued>queued_work);
 fe_bridge_work(&bridge.work.work);
 after_put_net=NULL;
 assert(!backlog_injections && bridge.read==bridge.write && !net.references);
 /* VLAN-aware access egress takes its VID from ingress, not the egress PVID. */
 br.filtering=true;lan.pvid=100;vlan.pvid=200;
 skb.extension=false;fe_bridge_wire(&bridge,&skb,&wire);fe_bridge_capture(&bridge,&skb,&input);
 assert(skb.saved.vid==100);
 br.filtering=false;
 /* Reverse direction: original PCP5/DEI1 survives VLAN subinterface removal. */
 fdb_source=&vlan;fdb_destination=&lan;
 pp.destination=32;lp.destination=0;
 wire.in=&pon;input.in=&vlan;output.out=&lan;
 skb.tagged=true;skb.vlan=0xb064;skb.vlan_proto=htons(0x8100);skb.extension=false;
 fe_bridge_wire(&bridge,&skb,&wire);
 skb.tagged=false;skb.vlan=0;skb.priority=0;
 fe_bridge_capture(&bridge,&skb,&input);
 assert(skb.saved.ingress==7 && skb.saved.port==70 && skb.saved.tag[0].tci==0xb064);
 fe_bridge_forwarded(&bridge,&skb,&output);fe_bridge_work(&bridge.work.work);
 assert(installed==2 && last.vlan_count==1 && last.ingress_tci[0]==0xb064);
 assert(last.action.vlan_set && last.action.vlan_count==0 && last.action.destination==0);
 /* Same MACs/session, different PPP protocol: use the real second CAM ID. */
 skb.frame[21]=0x57;skb.tagged=true;skb.vlan=0xb064;skb.extension=false;
 fe_bridge_wire(&bridge,&skb,&wire);skb.tagged=false;skb.vlan=0;
 fe_bridge_capture(&bridge,&skb,&input);fe_bridge_forwarded(&bridge,&skb,&output);
 fe_bridge_work(&bridge.work.work);
 assert(installed==3 && last.ppp_protocol_slot==9);
 /* STP and link changes withdraw the learned forwarding decision. */
 lan.state=0;bridge.flush=1;fe_bridge_work(&bridge.work.work);assert(deleted==3);
 lan.state=3;pon.carrier=false;
 fe_bridge_forwarded(&bridge,&skb,&output);fe_bridge_work(&bridge.work.work);
 assert(installed==3);
 assert(!net.references && fe.cookies.count==0);
 puts("Historical learner counterexample/EVTO fixture: same L2 key cannot authorize different L4 policies; model lifecycle passed (not production offload)");
}
'''
functions = ''.join(function(name) for name in ['fe_bridge_physical','fe_bridge_frame','fe_bridge_wire','fe_bridge_capture','fe_bridge_same','fe_bridge_forwarded','fe_bridge_ports','fe_bridge_learn','fe_bridge_work'])
with tempfile.TemporaryDirectory(dir=root/'artifacts',prefix='bridge-learning-') as directory:
    directory=Path(directory)
    (directory/'bridge.c').write_text(common+structs+backend+(drivers/'rtl9617c-fe-vlan.h').read_text()+functions+test)
    subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-fsanitize=address,undefined','-I'+str(drivers),'-I'+str(root/'port/overlay/target/linux/rtl9617c/files-6.18/include'),str(directory/'bridge.c'),'-o',str(directory/'bridge')],check=True)
    subprocess.run([str(directory/'bridge')],check=True)

# Compile the retired compatibility boundary without netfilter/workqueue stubs:
# reintroducing packet hooks, queued observations, or background work will fail
# compilation, rather than silently replacing them with a no-op host model.
policy = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
struct rtl_fe {bool enabled;};
struct rtl_fe_bridge;
static int scnprintf(char *buffer,size_t size,const char *format,...)
{
 va_list args;va_start(args,format);int result=vsnprintf(buffer,size,format,args);va_end(args);
 return result<0?0:result>=(int)size?(size?(int)size-1:0):result;
}
#include "rtl9617c-fe-bridge.h"
int main(void)
{
 struct rtl_fe fe={.enabled=true};char buffer[512],small[8];
 struct rtl_fe_bridge *bridge=fe_bridge_start(&fe);
 assert(bridge==NULL);
 assert(fe_bridge_stats(bridge,buffer,sizeof(buffer))>0);
 assert(strstr(buffer,"bridge_autolearn=0"));
 assert(strstr(buffer,"bridge_policy=explicit_flowtable_only"));
 assert(strstr(buffer,"bridge_work=0"));
 memset(small,'X',sizeof(small));
 assert(fe_bridge_stats(bridge,small,sizeof(small))==sizeof(small)-1);
 assert(small[sizeof(small)-1]==0);
 fe_bridge_stop(bridge);
 puts("Retired observation learner: no autonomous hooks or worker/allocation; native switchdev is tested separately");
}
'''
assert 'fe_install(' not in production
assert 'fe_bridge_learn(' not in production
with tempfile.TemporaryDirectory(dir=root/'artifacts',prefix='bridge-policy-') as directory:
    directory=Path(directory)
    (directory/'policy.c').write_text(policy)
    subprocess.run(['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                    '-I'+str(drivers),str(directory/'policy.c'),'-o',str(directory/'policy')],check=True)
    subprocess.run([str(directory/'policy')],check=True)
