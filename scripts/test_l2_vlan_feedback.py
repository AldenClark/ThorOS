#!/usr/bin/env python3
"""Execute the actual 238 VID-aware bridge feedback and admission functions.

The optional --kernel verifies identical applied production definitions. This
is a software ownership/state regression, not a VLAN wire-format silicon test.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

from test_l2_bridge_eligibility import function

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / "port/overlay/target/linux/rtl9617c/patches-6.18"
NAMES = {
    "br_rtl9617c_l2_vlan_port_eligible": "net/bridge/br_switchdev.c",
    "br_rtl9617c_fdb_learn_vid_publish": "net/bridge/br_fdb.c",
    "br_rtl9617c_fdb_learn_vid": "net/bridge/br_fdb.c",
    "br_rtl9617c_fdb_forget_vid": "net/bridge/br_fdb.c",
}

STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define BIT(n) (1UL << (n))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define rcu_access_pointer(x) (x)
#define ASSERT_RTNL() assert(rtnl)
#define CONFIG_BRIDGE_VLAN_FILTERING 1
#define IS_ENABLED(x) (x)
#define ETH_P_8021Q 0x8100
#define VLAN_VID_MASK 4095
#define htons(x) (x)
#define BR_LEARNING BIT(5)
#define BRIDGE_VLAN_INFO_MASTER BIT(0)
#define BRIDGE_VLAN_INFO_PVID BIT(1)
#define BRIDGE_VLAN_INFO_UNTAGGED BIT(2)
#define BRIDGE_VLAN_INFO_BRENTRY BIT(5)
#define BR_VLFLAG_NEIGH_SUPPRESS_ENABLED BIT(4)
#define BR_STATE_FORWARDING 3
#define BR_STATE_BLOCKING 4
#define BROPT_VLAN_ENABLED 0
#define RTM_NEWNEIGH 28
typedef uint64_t u64;
typedef uint16_t u16;
enum { BR_FDB_LOCAL, BR_FDB_STATIC, BR_FDB_ADDED_BY_USER,
       BR_FDB_ADDED_BY_EXT_LEARN, BR_FDB_OFFLOADED, BR_FDB_STICKY,
       BR_FDB_LOCKED };
struct net_device;
struct net_bridge_vlan {
 unsigned int vid,flags,priv_flags,state,msti;
 struct net_bridge_vlan *brvlan,*next;
 struct {void *tunnel_dst;uint64_t tunnel_id;} tinfo;
};
struct vlan_list {struct net_bridge_vlan *first;};
struct net_bridge_vlan_group {unsigned int pvid;struct vlan_list vlan_list;};
struct net_bridge_port;
struct net_bridge_fdb_entry {
 bool valid;
 unsigned char addr[6];u16 vid;
 unsigned long flags,updated,used;
 struct net_bridge_port *dst;
};
struct net_bridge {
 unsigned long options;
 unsigned int vlan_proto;
 int hash_lock;
 struct net_bridge_fdb_entry fdb[32];
};
struct net_bridge_port {
 unsigned int flags,state;
 struct net_bridge *br;
 struct net_bridge_vlan_group *vg;
};
struct net_device {struct net_bridge_port *port;bool base_eligible;};
struct rtl9617c_switch_guard {u64 generation;bool blocked;};
static bool rtnl=true,alloc_failure,publishing;
static unsigned int notifications,deletions,legacy_learns,legacy_forgets;
static unsigned long jiffies=1234;
static struct net_bridge_port *race_port;
static struct net_bridge_vlan *race_vlan;
static unsigned int race_kind;
static bool br_rtl9617c_l2_port_eligible(const struct net_device *d)
{return d->port && d->base_eligible;}
static struct net_bridge_port *br_port_get_rtnl(const struct net_device *d)
{ASSERT_RTNL();return d->port;}
static bool br_opt_get(const struct net_bridge *b,unsigned int bit)
{return !!(b->options&BIT(bit));}
static struct net_bridge_vlan_group *nbp_vlan_group(const struct net_bridge_port *p)
{ASSERT_RTNL();return p->vg;}
static unsigned int br_get_pvid(const struct net_bridge_vlan_group *vg)
{return vg?vg->pvid:0;}
#define list_for_each_entry(v,head,member) for((v)=(head)->first;(v);(v)=(v)->next)
static bool br_vlan_should_use(const struct net_bridge_vlan *v)
{return !(v->flags&BRIDGE_VLAN_INFO_MASTER) || (v->flags&BRIDGE_VLAN_INFO_BRENTRY);}
static unsigned int br_vlan_get_state(const struct net_bridge_vlan *v)
{return v->state;}
static struct net_bridge_vlan *br_vlan_find(const struct net_bridge_vlan_group *vg,u16 vid)
{struct net_bridge_vlan *v;if(!vg)return NULL;for(v=vg->vlan_list.first;v;v=v->next)if(v->vid==vid)return v;return NULL;}
static bool test_bit(unsigned int b,const unsigned long *p){return !!(*p&BIT(b));}
static void set_bit(unsigned int b,unsigned long *p){*p|=BIT(b);}
static void spin_lock_bh(int *p){assert(!*p);*p=1;}
static void spin_unlock_bh(int *p){assert(*p);*p=0;}
static struct net_bridge_fdb_entry *br_fdb_find(struct net_bridge *b,const unsigned char *a,u16 vid)
{unsigned int i;assert(b->hash_lock);for(i=0;i<32;i++)if(b->fdb[i].valid && b->fdb[i].vid==vid && !memcmp(b->fdb[i].addr,a,6))return &b->fdb[i];return NULL;}
static struct net_bridge_fdb_entry *fdb_create(struct net_bridge *b,struct net_bridge_port *p,const unsigned char *a,u16 vid,unsigned long flags)
{unsigned int i;assert(publishing && b->hash_lock);if(alloc_failure)return NULL;for(i=0;i<32;i++)if(!b->fdb[i].valid){b->fdb[i]=(struct net_bridge_fdb_entry){.valid=true,.vid=vid,.dst=p,.flags=flags,.used=jiffies,.updated=jiffies};memcpy(b->fdb[i].addr,a,6);return &b->fdb[i];}return NULL;}
static void fdb_notify(struct net_bridge *b,const struct net_bridge_fdb_entry *f,int type,bool sw)
{assert(b->hash_lock && !publishing && f && type==RTM_NEWNEIGH && !sw);notifications++;}
static void fdb_delete(struct net_bridge *b,struct net_bridge_fdb_entry *f,bool sw)
{assert(b->hash_lock && f->valid && !sw);f->valid=false;deletions++;}
static int rtl9617c_switch_guard_publish(struct rtl9617c_switch_guard *g,u64 epoch,int(*fn)(void*),void *ctx)
{int ret;if(g->blocked || g->generation!=epoch)return -EAGAIN;assert(!publishing);publishing=true;
 if(race_kind==1)race_port->state=BR_STATE_BLOCKING;
 if(race_kind==2)race_port->flags&=~BR_LEARNING;
 if(race_kind==3)race_vlan->state=BR_STATE_BLOCKING;
 if(race_kind==4)race_port->vg->vlan_list.first=NULL;
 if(race_kind==5)race_port->br->options=0;
 ret=fn(ctx);publishing=false;return ret;}
static int br_rtl9617c_fdb_learn(const struct net_device *d,const unsigned char *a,struct rtl9617c_switch_guard *g,u64 e)
{assert(d->port && a && g && e);legacy_learns++;return 19;}
static bool br_rtl9617c_fdb_forget(const struct net_device *d,const unsigned char *a)
{assert(d && a);legacy_forgets++;return true;}
'''

TESTS = r'''
int main(void)
{
 struct net_bridge br={.options=BIT(BROPT_VLAN_ENABLED),.vlan_proto=ETH_P_8021Q};
 struct net_bridge other=br;
 struct net_bridge_vlan global={.vid=10,.flags=BRIDGE_VLAN_INFO_MASTER,.state=3};
 struct net_bridge_vlan global2=global;
 struct net_bridge_vlan v={.vid=10,.brvlan=&global,.state=3};
 struct net_bridge_vlan v2={.vid=20,.brvlan=&global2,.state=3};
 struct net_bridge_vlan_group vg={.vlan_list={.first=&v}};
 struct net_bridge_port p={.br=&br,.vg=&vg,.state=3,.flags=BR_LEARNING};
 struct net_bridge_port p2=p;
 struct net_device dev={.port=&p,.base_eligible=true},dev2={.port=&p2,.base_eligible=true};
 struct rtl9617c_switch_guard guard={.generation=17};
 const unsigned char mac[6]={2,1,2,3,4,5};
 struct net_bridge_fdb_entry before[32];
 unsigned int n,i;
 global2.vid=20;v.next=&v2;
 assert(br_rtl9617c_l2_vlan_port_eligible(&dev));
 /* Context-only master rows are sufficient for pure transit. */
 assert(!(global.flags&BRIDGE_VLAN_INFO_BRENTRY));
 dev.base_eligible=false;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));dev.base_eligible=true;
 br.options=0;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));br.options=1;
 br.vlan_proto=0x88a8;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));br.vlan_proto=ETH_P_8021Q;
 vg.pvid=10;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));vg.pvid=0;
 for(i=0;i<2;i++){v.flags=i?BRIDGE_VLAN_INFO_PVID:BRIDGE_VLAN_INFO_UNTAGGED;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));}v.flags=0;
 for(i=0;i<5;i++){v.state=i;if(i!=3)assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));}v.state=3;
 for(i=0;i<5;i++){global.state=i;if(i!=3)assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));}global.state=3;
 global.msti=1;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));global.msti=0;
 v.tinfo.tunnel_dst=&v;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));v.tinfo.tunnel_dst=NULL;
 v.tinfo.tunnel_id=1;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));v.tinfo.tunnel_id=0;
 v.priv_flags=BR_VLFLAG_NEIGH_SUPPRESS_ENABLED;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));v.priv_flags=0;
 vg.vlan_list.first=NULL;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));vg.vlan_list.first=&v;
 v.brvlan=NULL;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));v.brvlan=&global;
 v.vid=0;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));v.vid=4095;assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));v.vid=10;
 /* All real VIDs retain their exact FDB namespace; no accidental VID0. */
 v.next=NULL;
 for(i=1;i<4095;i++){
  v.vid=global.vid=i;
  assert(br_rtl9617c_l2_vlan_port_eligible(&dev));
  assert(!br_rtl9617c_fdb_learn_vid(&dev,mac,i,&guard,17));
  assert(br.fdb[0].valid && br.fdb[0].vid==i);
  assert(br_rtl9617c_fdb_forget_vid(&dev,mac,i));
 }
 v.vid=global.vid=10;v.next=&v2;
 assert(br_rtl9617c_fdb_learn_vid(&dev,mac,4095,&guard,17)==-EINVAL);
 assert(!br_rtl9617c_fdb_forget_vid(&dev,mac,4095));
 assert(br_rtl9617c_fdb_learn_vid(&dev,mac,0,&guard,17)==-EOPNOTSUPP);
 assert(!legacy_learns);br.options=0;
 assert(br_rtl9617c_fdb_learn_vid(&dev,mac,0,&guard,17)==19);assert(legacy_learns==1);
 assert(br_rtl9617c_fdb_forget_vid(&dev,mac,0));assert(legacy_forgets==1);br.options=1;
 /* Same MAC in different VIDs and distinct bridges remains independent. */
 assert(!br_rtl9617c_fdb_learn_vid(&dev,mac,10,&guard,17));
 assert(!br_rtl9617c_fdb_learn_vid(&dev,mac,20,&guard,17));
 assert(br.fdb[0].vid==10 && br.fdb[1].vid==20);
 n=notifications;jiffies++;
 assert(!br_rtl9617c_fdb_learn_vid(&dev2,mac,10,&guard,17));
 assert(br.fdb[0].dst==&p2 && br.fdb[1].dst==&p && notifications==n+1);
 assert(!br_rtl9617c_fdb_forget_vid(&dev,mac,10));
 p2.br=&other;assert(!br_rtl9617c_fdb_learn_vid(&dev2,mac,10,&guard,17));
 assert(other.fdb[0].vid==10 && br.fdb[0].dst==&p2);p2.br=&br;
 /* Protected replacements and stale generations are byte-for-byte inert. */
 for(i=BR_FDB_LOCAL;i<=BR_FDB_LOCKED;i++){
  if(i==BR_FDB_ADDED_BY_EXT_LEARN || i==BR_FDB_OFFLOADED)continue;
  br.fdb[0].flags=BIT(i)|BIT(BR_FDB_ADDED_BY_EXT_LEARN);
  memcpy(before,br.fdb,sizeof(before));
  assert(br_rtl9617c_fdb_learn_vid(&dev,mac,10,&guard,17)==-EEXIST);
  assert(!br_rtl9617c_fdb_forget_vid(&dev2,mac,10));
  assert(!memcmp(before,br.fdb,sizeof(before)));
 }
 br.fdb[0].flags=BIT(BR_FDB_ADDED_BY_EXT_LEARN);
 memcpy(before,br.fdb,sizeof(before));
 assert(br_rtl9617c_fdb_learn_vid(&dev,mac,10,&guard,16)==-EAGAIN);
 guard.blocked=true;assert(br_rtl9617c_fdb_learn_vid(&dev,mac,10,&guard,17)==-EAGAIN);guard.blocked=false;
 assert(!memcmp(before,br.fdb,sizeof(before)));
 /* Recheck exactly at the guarded publication boundary, including refresh. */
 race_port=&p;race_vlan=&v;
 for(i=1;i<=5;i++){
  race_kind=i;memcpy(before,br.fdb,sizeof(before));
  assert(br_rtl9617c_fdb_learn_vid(&dev,mac,10,&guard,17)==-EOPNOTSUPP);
  assert(!memcmp(before,br.fdb,sizeof(before)));
  p.state=v.state=3;p.flags=BR_LEARNING;vg.vlan_list.first=&v;br.options=1;
 }
 race_kind=0;
 /* Removal after VLAN membership disappeared must still clear only old VID. */
 vg.vlan_list.first=NULL;
 assert(br_rtl9617c_fdb_forget_vid(&dev2,mac,10));
 assert(!br.fdb[0].valid && br.fdb[1].valid && br.fdb[1].vid==20);
 assert(br_rtl9617c_fdb_forget_vid(&dev,mac,20));
 vg.vlan_list.first=&v;alloc_failure=true;
 assert(br_rtl9617c_fdb_learn_vid(&dev,mac,10,&guard,17)==-ENOMEM);alloc_failure=false;
 dev.port=NULL;
 assert(br_rtl9617c_fdb_learn_vid(&dev,mac,10,&guard,17)==-ENODEV);
 assert(!br_rtl9617c_fdb_forget_vid(&dev,mac,10));
 assert(!br_rtl9617c_l2_vlan_port_eligible(&dev));
 assert(!br.hash_lock && !other.hash_lock && !publishing);
 printf("PASS: 4094 VID lifetimes, cross-VID/bridge identity, admission, protected FDB and 5 publication races (%u notifications, %u deletions)\n",notifications,deletions);
 return 0;
}
'''


def production(kernel=None):
    text = (PATCHES / "238-native-bridge-vlan-feedback.patch").read_text()
    added = "\n".join(s[1:] for s in text.splitlines()
                      if s.startswith("+") and not s.startswith("+++"))
    context = re.search(r"struct br_rtl9617c_vlan_learn_ctx \{[^}]+\};", added).group(0)
    if kernel:
        assert context in (kernel / "net/bridge/br_fdb.c").read_text()
    sources = [context]
    for name, path in NAMES.items():
        actual = function(added, name)
        if kernel:
            assert actual == function((kernel / path).read_text(), name), name
        sources.append(actual)
    return "\n\n".join(sources)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    source = production(args.kernel)
    variants = {"production": source}
    if args.mutants:
        changes = {
            "collapse_vid_lookup": ("br_fdb_find(br, ctx->addr, ctx->vid)", "br_fdb_find(br, ctx->addr, 0)"),
            "collapse_vid_create": ("fdb_create(br, ctx->port, ctx->addr, ctx->vid,", "fdb_create(br, ctx->port, ctx->addr, 0,"),
            "forget_wrong_vid": ("br_fdb_find(p->br, addr, vid)", "br_fdb_find(p->br, addr, 20)"),
            "omit_vlan_state": ("br_vlan_get_state(v) != BR_STATE_FORWARDING ||\n\t    !v->brvlan", "false ||\n\t    !v->brvlan"),
            "admit_pvid_edit": ("if (!vg || br_get_pvid(vg))", "if (!vg)"),
            "require_local_membership": ("!global || READ_ONCE(global->msti)", "!global || !(global->flags & BRIDGE_VLAN_INFO_BRENTRY) || READ_ONCE(global->msti)"),
        }
        for name, (before, after) in changes.items():
            assert source.count(before) == 1, name
            variants[name] = source.replace(before, after, 1)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    with tempfile.TemporaryDirectory(prefix="l2-vlan-feedback-") as temp:
        for name, code in variants.items():
            cfile, binary = Path(temp) / (name + ".c"), Path(temp) / name
            cfile.write_text(STUBS + "\n" + code + "\n" + TESTS)
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
                            "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                            "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                            str(cfile), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, env=env)
            if name == "production":
                assert result.returncode == 0, result.stdout + result.stderr
                print(result.stdout, end="")
            else:
                assert result.returncode != 0 and "assert" in result.stderr.lower(), name + result.stderr
                print("PASS: rejected", name)


if __name__ == "__main__":
    main()
