#!/usr/bin/env python3
"""Execute the production QM poll and MCE CPU decoder together.

DMA and kernel endpoint containers are modelled; neither the actual poll nor
rtl_fe_mcast_rx is rewritten. This tests retirement and endpoint selection,
not ASIC producer retirement, policy publication or the bridge implementation.
The latter have separate cold-owner, policy-race and dispatch regressions.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"


def function(text, name):
    found = re.search(r"^(?:static\s+)?(?:inline\s+)?[^\n;{}]+\b" + name + r"\(", text, re.M)
    if found is None:
        raise AssertionError("function missing: " + name)
    start = text.index("{", found.start())
    end, depth = start + 1, 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[found.start():end]


def replace_function(text, name, replacement):
    return text.replace(function(text, name), replacement, 1)


GLOBALS = r'''
static unsigned hardware_write,retired,pushed,allocations,frees;
static unsigned guard_calls,hook_calls,normal_calls,copy_calls,pon_calls;
static unsigned target_port,packet_kind,guard_generation;
static bool alloc_fail,guard_armed,change_guard_during_lookup;
static struct net_device master,*selected_master,*wanted_input;
static struct rtl_fe *wanted_fe;
static u32 wanted_h0,wanted_h1;
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p,v) (*(p)=(v))
#define __maybe_unused __attribute__((unused))
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
static bool is_link_local_ether_addr(const unsigned char *a) {
 const unsigned char prefix[]={1,0x80,0xc2,0,0};
 return !memcmp(a,prefix,5)&&a[5]<=15;
}
static void packet_expected(u8 data[64]) {
 memset(data,0xa5,64);data[0]=2;data[6]=2;
 if(packet_kind==1)memset(data,255,6);
 if(packet_kind==2){data[0]=1;data[1]=0;data[2]=0x5e;}
 data[12]=8;data[13]=0;data[14]=0x45;data[23]=17;
 data[36]=0;data[37]=7;
}
'''


REPLACEMENTS = {
    "skb_ext_find": r'''
static void *skb_ext_find(struct sk_buff *skb,unsigned id) {
 assert(id==SKB_EXT_RTL9617C_MCAST);return skb->has_copy?&skb->copy:NULL;
}
static void *skb_ext_add(struct sk_buff *skb,unsigned id) {
 assert(id==SKB_EXT_RTL9617C_MCAST && retired==1 && pushed==0);
 assert(skb->data==skb->storage && skb->len==64 && !skb->protocol);
 allocations++;if(alloc_fail)return NULL;skb->has_copy=true;return &skb->copy;
}''',
    "netdev_master_upper_dev_get_rcu": r'''
static struct net_device *netdev_master_upper_dev_get_rcu(struct net_device *input) {
 assert(input==wanted_input && allocations==1 && retired==1 && !pushed);
 if(change_guard_during_lookup)guard_generation++;
 return selected_master;
}''',
    "rtl9617c_mcast_copy_valid": r'''
static bool rtl9617c_mcast_copy_valid(const struct sk_buff *skb,
 const struct net_device *input,const struct net_device *upper) {
 /* Container-only endpoint/guard shim. The actual core guard and writer
  * interleavings are exercised independently by test_l2_policy_races. */
 guard_calls++;
 return skb->has_copy && guard_armed && input && upper &&
  skb->copy.owner==41 && skb->copy.generation==guard_generation &&
  skb->copy.ingress_ifindex==input->ifindex &&
  skb->copy.master_ifindex==upper->ifindex && input->net==upper->net;
}''',
    "readl": r'''
static u32 readl(void *reg) {
 unsigned off=(u8 *)reg-(u8 *)active->ni;
 if(off==0x3218)return 0;
 assert(off>=EPP_WRITE && off<EPP_WRITE+32 && !(off&3));
 return off==EPP_WRITE?hardware_write:0;
}''',
    "writel": r'''
static void writel(u32 value,void *reg) {
 assert((u8 *)reg-(u8 *)active->ni==EPP_READ && value==8);retired++;
}''',
    "dma_sync_single_for_cpu": r'''
static void dma_sync_single_for_cpu(void *device,dma_addr_t address,unsigned bytes,int dir) {
 (void)address;assert(device==active->device && (bytes==64 || bytes==2048) && dir==DMA_FROM_DEVICE);
}''',
    "rtl_qm_try_push": r'''
static int rtl_qm_try_push(void *ctx,unsigned address,unsigned eq) {
 assert(ctx==active && retired==1 && address==active->memory_dma+RTL_QM_PAYLOAD_OFFSET && eq==4);
 assert(copy_calls+normal_calls+pon_calls+frees==1);
 pushed++;return 0;
}''',
    "dev_kfree_skb_any": r'''
static void dev_kfree_skb_any(struct sk_buff *skb) {
 assert(retired==1 && pushed==0);frees++;free(skb);
}''',
    "rtl_fe_switch_rx": r'''
static void rtl_fe_switch_rx(struct rtl_fe *fe,struct sk_buff *skb,unsigned source,u32 h0,u32 h1) {
 assert(fe==wanted_fe && source==target_port && source<5);
 assert(h0==wanted_h0 && h1==wanted_h1 && retired==1 && pushed==0);
 assert(skb->len==64 && skb->data==skb->storage && !skb->protocol && !skb->offload_fwd_mark);
 if(skb->has_copy)assert(guard_calls==1 && allocations==1 && ((h1>>9)&63)==27);
 hook_calls++;
}''',
    "eth_type_trans": r'''
static unsigned eth_type_trans(struct sk_buff *skb,struct net_device *input) {
 assert(input==wanted_input && hook_calls==1);skb->dev=input;
 skb->data+=14;skb->len-=14;return ETH_P_IP;
}''',
    "napi_gro_receive": r'''
static void napi_gro_receive(struct napi_struct *napi,struct sk_buff *skb) {
 (void)napi;u8 expected[64];packet_expected(expected);
 assert(!skb->has_copy && !allocations && !guard_calls && !copy_calls && !pon_calls);
 assert(skb->dev==wanted_input && skb->len==50 && !memcmp(skb->data,expected+14,50));
 assert(retired==1 && !pushed && hook_calls==1);normal_calls++;free(skb);
}''',
    "netif_receive_skb": r'''
static void netif_receive_skb(struct sk_buff *skb) {
 u8 expected[64];packet_expected(expected);
 assert(skb->has_copy && !skb->offload_fwd_mark && guard_calls==1 && hook_calls==1);
 assert(skb->copy.owner==41 && skb->copy.generation==7 && skb->copy.vid==0);
 assert(skb->copy.ingress_ifindex==(int)target_port+100 && skb->copy.master_ifindex==999);
 assert(skb->copy.token==64+target_port && skb->dev==wanted_input);
 assert(skb->len==50 && !memcmp(skb->data,expected+14,50));
 assert(retired==1 && !pushed && !normal_calls && !pon_calls);copy_calls++;free(skb);
}''',
    "pon_receive": r'''
static void pon_receive(struct rtl9617c_ni_endpoint *endpoint,struct napi_struct *napi,
 struct sk_buff *skb,unsigned metadata) {
 (void)endpoint;(void)napi;assert(!skb->has_copy && !allocations && !guard_calls);
 assert(!hook_calls && retired==1 && !pushed && metadata==(7U|(64U<<8)));
 pon_calls++;free(skb);
}''',
}


CASES = r'''
static void setup(struct rtl_qm_rx *rx,struct net_device *owner,struct net_device ports[5],
 struct rtl_fe *fe,struct rtl_fe_mcast *mc,unsigned port,unsigned cpu,unsigned format,unsigned packet) {
 *rx=(struct rtl_qm_rx){.memory_dma=0x4000000,.ring_dma=0x6000000,.device=owner,.fe=fe};
 rx->memory=calloc(1,RTL_QM_MEMORY_BYTES);rx->ring_memory=calloc(1,RTL_QM_RING_MEMORY_BYTES);
 rx->ni=calloc(1,65536);assert(rx->memory&&rx->ring_memory&&rx->ni);
 memset(owner,0,sizeof(*owner));memset(ports,0,5*sizeof(*ports));
 for(unsigned i=0;i<5;i++){ports[i].running=true;ports[i].ifindex=100+i;ports[i].net=1;rx->lan[i]=&ports[i];}
 memset(mc,0,sizeof(*mc));fe->mcast=mc;mc->state.contract_ready=1;
 mc->state.active_owner=41;mc->state.active_generation=7;
 mc->state.token[64+port]=(struct rtl_mcast_token){.owner=41,.generation=7,
  .ingress_ifindex=100+port,.master_ifindex=999,.vid=0,.ingress=port,.allocated=1,.published=1};
 fe_mcast_arm(fe,7);
 master=(struct net_device){.ifindex=999,.net=1};selected_master=&master;
 guard_armed=true;guard_generation=7;alloc_fail=change_guard_during_lookup=false;
 active=rx;target_port=port;packet_kind=packet;wanted_input=&ports[port];wanted_fe=fe;
 wanted_h0=(cpu<<31)|((64+port)<<18)|(packet<<11);
 wanted_h1=(format<<30)|((64+cpu*8)<<15)|(27<<9)|(16<<3)|7;
 unsigned off=RTL_QM_PAYLOAD_OFFSET,header=8+cpu*8;
 put(__builtin_bswap32(wanted_h0),rx->memory+off+RTL_QM_HEADROOM);
 put(__builtin_bswap32(wanted_h1),rx->memory+off+RTL_QM_HEADROOM+4);
 packet_expected(rx->memory+off+RTL_QM_HEADROOM+header);
 put((rx->memory_dma+off)|0x54,rx->ring_memory);put(0,rx->ring_memory+4);
 hardware_write=8;retired=pushed=allocations=frees=guard_calls=hook_calls=normal_calls=copy_calls=pon_calls=0;
}
static void headers(struct rtl_qm_rx *rx) {
 put(__builtin_bswap32(wanted_h0),rx->memory+RTL_QM_PAYLOAD_OFFSET+RTL_QM_HEADROOM);
 put(__builtin_bswap32(wanted_h1),rx->memory+RTL_QM_PAYLOAD_OFFSET+RTL_QM_HEADROOM+4);
}
static void cleanup(struct rtl_qm_rx *rx){free(rx->memory);free(rx->ring_memory);free(rx->ni);}
int main(void) {
 struct rtl_qm_rx rx;struct net_device owner,ports[5];struct rtl_fe fe;
 struct rtl_fe_mcast mc;struct napi_struct napi={.dev=&owner};unsigned cases=0;
 struct rtl9617c_ni_endpoint endpoint={.receive=pon_receive};
 for(unsigned port=0;port<5;port++)for(unsigned cpu=0;cpu<2;cpu++)
 for(unsigned format=0;format<3;format++)for(unsigned packet=0;packet<4;packet++) {
  setup(&rx,&owner,ports,&fe,&mc,port,cpu,format,packet);rx.pon=&endpoint;
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
  assert(copy_calls==1 && !normal_calls && !pon_calls && !frees && retired==1 && pushed==1);
  assert(ports[port].stats.rx_packets==1 && ports[port].stats.rx_bytes==64);
  assert(mc.state.rx_copies==1 && !mc.state.rx_rejected && !owner.stats.rx_dropped);
  cleanup(&rx);cases++;
 }
 for(unsigned port=0;port<5;port++)for(unsigned failure=0;failure<8;failure++) {
  setup(&rx,&owner,ports,&fe,&mc,port,1,2,1);rx.pon=&endpoint;
  switch(failure) {
   case 0:rx.lan[port]=NULL;break;
   case 1:ports[port].running=false;break;
   case 2:ports[port].ifindex++;break;
   case 3:selected_master=NULL;break;
   case 4:master.ifindex++;break;
   case 5:master.net++;break;
   case 6:guard_armed=false;break;
   case 7:change_guard_during_lookup=true;break;
  }
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
  assert(!copy_calls && !normal_calls && !pon_calls && !hook_calls && frees==1);
  assert(allocations==1 && retired==1 && pushed==1 && owner.stats.rx_dropped==1);
  assert(guard_calls==(failure>=2) && !ports[port].stats.rx_packets);
  cleanup(&rx);cases++;
 }
 for(unsigned failure=0;failure<15;failure++) {
  setup(&rx,&owner,ports,&fe,&mc,0,0,2,1);rx.pon=&endpoint;
  u8 *data=rx.memory+RTL_QM_PAYLOAD_OFFSET+RTL_QM_HEADROOM+8;
  switch(failure) {
   case 0:mc.state.active_generation++;break;
   case 1:mc.state.active_owner++;break;
   case 2:mc.state.token[64].allocated=0;break;
   case 3:mc.state.token[64].published=0;break;
   case 4:fe_mcast_revoke(&fe);break;
   case 5:alloc_fail=true;break;
   case 6:wanted_h0&=~(511U<<18);break;
   case 7:wanted_h0|=1U<<14;break;
   case 8:wanted_h1|=3U<<30;break;
   case 9:data[12]=0x81;data[13]=0;break;
   case 10:data[12]=0x88;data[13]=0xa8;break;
   case 11:memcpy(data,(u8[]){1,0x80,0xc2,0,0,0},6);break;
   case 12:fe.mcast=NULL;break;
   case 13:rx.fe=NULL;break;
   case 14:mc.state.token[64].ingress=5;break;
  }
  headers(&rx);assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
  assert(!copy_calls && !normal_calls && !pon_calls && !hook_calls && !guard_calls && frees==1);
  assert(retired==1 && pushed==1 && owner.stats.rx_dropped==1 && allocations==(failure==5));
  assert(mc.state.rx_no_memory==(failure==5));cleanup(&rx);cases++;
 }
 /* Same token-like bits on a real LAN or PON frame must remain ordinary. */
 for(unsigned pon=0;pon<2;pon++) {
  setup(&rx,&owner,ports,&fe,&mc,0,0,0,0);rx.pon=&endpoint;
  wanted_h1=(wanted_h1&~(63U<<9))|((pon?7U:0U)<<9);headers(&rx);
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1 && !copy_calls && !allocations && !frees);
  assert(normal_calls==!pon && pon_calls==pon && retired==1 && pushed==1);
  cleanup(&rx);cases++;
 }
 printf("QM plus production MCE decoder: %u restored-source, direct-receive, retirement, epoch, allocation and endpoint cases passed\n",cases);
}
'''


def source_text():
    tree = ast.parse((ROOT / "scripts/fixtures/qm_cached_epp_model.py").read_text())
    common = next(ast.literal_eval(node.value) for node in tree.body
                  if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                  target.id == "common" for target in node.targets))
    header = (ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/include/linux/rtl9617c-mcast.h").read_text()
    record = re.search(r"struct rtl9617c_mcast_copy \{.*?\n\};", header, re.S).group(0)
    common = common.replace("struct rtl9617c_mcast_copy {int ingress_ifindex;};", "")
    common = common.replace("struct sk_buff {", record + "\nstruct sk_buff {bool has_copy,offload_fwd_mark;struct rtl9617c_mcast_copy copy;")
    common = common.replace("int ifindex;struct", "int ifindex;unsigned net;struct")
    common = common.replace("#define SKB_EXT_RTL9617C_MCAST 1", "#define SKB_EXT_RTL9617C_MCAST 1\nstruct rtl_fe;\n" + GLOBALS)
    common = common.replace("struct rtl_fe {unsigned int unused;};", '#include "rtl9617c-mcast-state.h"\nstruct rtl_fe_mcast {struct rtl_mcast_state state;};\nstruct rtl_fe {struct rtl_fe_mcast *mcast;};')
    for name, replacement in REPLACEMENTS.items():
        common = replace_function(common, name, replacement)
    common = replace_function(common, "rtl_fe_mcast_rx", "")
    decoder_header = (DRIVER / "rtl9617c-fe-mcast.h").read_text()
    decoder = "\n".join(function(decoder_header, name) for name in
                        ("fe_mcast_revoke", "fe_mcast_arm", "rtl_fe_mcast_rx"))
    qm = (DRIVER / "rtl9617c-qm.c").read_text()
    poll = qm[qm.index("static void rtl_qm_rx_retire("):qm.index("\nssize_t rtl_qm_rx_voq_state(")]
    return common, decoder, poll


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(common, decoder, poll):
    with tempfile.TemporaryDirectory(prefix="qm-mcast-copy-") as directory:
        work = Path(directory)
        (work / "linux").mkdir()
        (work / "linux/errno.h").write_text("#include <asm-generic/errno.h>\n")
        (work / "linux/string.h").write_text("#include <string.h>\n")
        (work / "test.c").write_text(common + decoder + poll + CASES)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-parameter", "-Wno-misleading-indentation",
                        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(work), "-I", str(DRIVER),
                        "-I", str(ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/include/linux"),
                        str(work / "test.c"), "-o", str(work / "test")], check=True)
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0"
        env["UBSAN_OPTIONS"] = "halt_on_error=1"
        return subprocess.run([str(work / "test")], capture_output=True, text=True,
                              env=env, preexec_fn=no_core)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    common, decoder, poll = source_text()
    result = run(common, decoder, poll)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    print(result.stdout, end="")
    rejected = []
    if args.mutants:
        changes = {
            "copy_into_gro": ("poll", "if (mcast_copy)\n", "if (0)\n"),
            "skip_endpoint_guard": ("poll", "!rtl9617c_mcast_copy_valid(skb, input,", "0 && !rtl9617c_mcast_copy_valid(skb, input,"),
            "decode_before_retire": ("poll", "rtl_qm_rx_retire(rx, cos, command, refill_buffer);\n\t\t\tmcast_copy", "mcast_copy"),
            "lost_original_source": ("decoder", "*source = token->ingress;", "*source = 27;"),
            "stale_decoder_epoch": ("decoder", "token->generation != READ_ONCE(state->active_generation)", "0"),
        }
        for name, (unit, before, after) in changes.items():
            text = poll if unit == "poll" else decoder
            if before not in text:
                raise AssertionError("mutation target missing: " + name)
            changed = text.replace(before, after, 1)
            result = run(common, changed if unit == "decoder" else decoder,
                         changed if unit == "poll" else poll)
            if not result.returncode:
                raise AssertionError("mutation survived: " + name)
            rejected.append(name)
        print("QM/MCE integration mutation controls rejected: " + ", ".join(rejected))
    artifact = ROOT / "artifacts/qm-mcast-copy.json"
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_text(json.dumps({
        "cases": 177, "mutations_rejected": rejected, "hardware_verified": False,
        "production_decoder_sha256": hashlib.sha256(decoder.encode()).hexdigest(),
        "production_poll_sha256": hashlib.sha256(poll.encode()).hexdigest(),
        "scope": "actual production QM poll plus actual MCE CPU decoder; endpoint/guard containers modelled",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
