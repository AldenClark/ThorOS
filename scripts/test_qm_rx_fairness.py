#!/usr/bin/env python3
"""Execute the production NAPI poll under continuous multi-VOQ load.

Hardware publishes separate EPP bytes; the CPU sees them only after DMA
sync. This proves bounded software service/ownership, not ASIC throughput,
strict-priority QoS or a physical PON latency guarantee.
"""
import argparse
import ast
from pathlib import Path
import resource
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"


def function(text, name):
    start = text.index(name + "(")
    start = text.rfind("\n", 0, start) + 1
    end = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


tree = ast.parse((ROOT / "scripts/fixtures/qm_cached_epp_model.py").read_text())
model = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "common" for t in n.targets))
start = model.index("static u32 readl(")
end = model.index("static bool rtl_rx_checksum_valid", start)
model = model[:start] + r'''
static u8 hardware[RTL_QM_RING_MEMORY_BYTES];
static unsigned prod[8],cons[8],seen_packets[8],ring_syncs[8],pointer_reads;
static unsigned sequence[4096],sequence_count,inject_queue,inject_count;
static unsigned checksum_word,checksum_validations;
static bool free_buffer[1024];
static void publish(unsigned q,unsigned n);
static u32 readl(void *p) {
 unsigned r=(u8 *)p-(u8 *)active->ni;
 if(r==0x3218)return checksum_word;
 assert(r>=EPP_WRITE && r<EPP_WRITE+32 && !(r&3));
 pointer_reads++;
 return (prod[(r-EPP_WRITE)/4]%RTL_QM_RING_COMMANDS)*8;
}
static void writel(u32 value,void *p) {
 unsigned r=(u8 *)p-(u8 *)active->ni;
 assert(r>=EPP_READ && r<EPP_READ+32 && !(r&3));
 unsigned q=(r-EPP_READ)/4;
 unsigned delta=(value-(cons[q]%RTL_QM_RING_COMMANDS)*8)&(RTL_QM_RING_BYTES-1);
 assert(delta==8 && cons[q]<prod[q]);cons[q]++;
}
static void dma_sync_single_for_cpu(void *d,dma_addr_t address,unsigned n,int dir) {
 assert(d==active->device && dir==DMA_FROM_DEVICE && n);
 if(address>=active->ring_dma && address<active->ring_dma+RTL_QM_RING_MEMORY_BYTES) {
  unsigned offset=address-active->ring_dma,q=offset/RTL_QM_RING_BYTES;
  assert(!(offset%64) && !(n%64) && offset%RTL_QM_RING_BYTES+n<=RTL_QM_RING_BYTES);
  memcpy(active->ring_memory+offset,hardware+offset,n);ring_syncs[q]++;
 } else {
  unsigned offset=address-active->memory_dma;
  assert(n==2048 && offset<RTL_QM_MEMORY_BYTES && !(offset%2048));
  assert(!free_buffer[offset/2048]);
 }
}
static int rtl_qm_try_push(void *context,unsigned address,unsigned eq) {
 struct rtl_qm_rx *rx=context;unsigned offset=address-rx->memory_dma,id=offset/2048;
 assert(!(offset%2048) && id<1024 && eq==4+id/512 && !free_buffer[id]);
 /* An EPP is already retired before this sole buffer owner is returned. */
 assert(cons[id/128]>0);free_buffer[id]=true;return 0;
}
''' + model[end:]
model = model.replace(function(model, "rtl_rx_checksum_valid"), r'''
static bool rtl_rx_checksum_valid(u32 command,const void *packet,unsigned length) {
 (void)command;(void)packet;assert(length==64);checksum_validations++;return true;
}
''')
model = model.replace(function(model, "received"), r'''
static void received(struct sk_buff *s) {
 unsigned id=get_unaligned_be32(s->data+28),q=id>>24,number=id&0xffffff;
 assert(q<8 && number==cons[q]-1 && sequence_count<4096);
 u8 expected[64];packet_bytes(id,expected);
 assert(s->len==50 && !memcmp(s->data,expected+14,50));
 assert(s->ip_summed==((checksum_word!=~0U && (checksum_word&BIT(16)))?CHECKSUM_UNNECESSARY:0));
 seen_packets[q]++;sequence[sequence_count++]=q;free(s);
 if(inject_count) {
  unsigned count=inject_count;inject_count=0;publish(inject_queue,count);
 }
}
''')

CASES = r'''
static void publish(unsigned q,unsigned n) {
 for(unsigned i=0;i<n;i++) {
  assert(prod[q]-cons[q]<127);
  unsigned id=q*128+prod[q]%128,offset=id*2048;
  assert(free_buffer[id]);free_buffer[id]=false;
  put(0,active->memory+offset+RTL_QM_HEADROOM);
  put(__builtin_bswap32(64U<<15),active->memory+offset+RTL_QM_HEADROOM+4);
  packet_bytes((q<<24)|prod[q],active->memory+offset+RTL_QM_HEADROOM+8);
  void *entry=hardware+q*RTL_QM_RING_BYTES+(prod[q]%RTL_QM_RING_COMMANDS)*8;
  put((active->memory_dma+offset)|(4+id/512)|BIT(4)|BIT(6),entry);put(0,entry+4);
  prod[q]++;
 }
}
static void setup(struct rtl_qm_rx *rx,struct net_device *owner,
                  struct net_device *input,unsigned origin) {
 *owner=(struct net_device){.running=true};*input=(struct net_device){.running=true};
 *rx=(struct rtl_qm_rx){.device=owner,.memory_dma=0x4000000,.ring_dma=0x6000000,.next_voq=7};
 rx->ni=calloc(1,65536);rx->memory=calloc(1,RTL_QM_MEMORY_BYTES);
 rx->ring_memory=malloc(RTL_QM_RING_MEMORY_BYTES);assert(rx->ni && rx->memory && rx->ring_memory);
 memset(rx->ring_memory,0xcc,RTL_QM_RING_MEMORY_BYTES);memset(hardware,0x55,sizeof(hardware));
 memset(free_buffer,1,sizeof(free_buffer));memset(seen_packets,0,sizeof(seen_packets));
 memset(ring_syncs,0,sizeof(ring_syncs));sequence_count=pointer_reads=inject_count=kind=0;
 checksum_word=checksum_validations=0;
 for(unsigned q=0;q<8;q++){prod[q]=cons[q]=origin;rx->read[q]=(origin%256)*8;}
 rx->lan[0]=input;active=rx;
}
static void cleanup(struct rtl_qm_rx *rx) {free(rx->ni);free(rx->memory);free(rx->ring_memory);}
int main(void) {
 struct rtl_qm_rx rx;struct net_device owner,input;struct napi_struct napi={.dev=&owner};
 const unsigned budgets[]={1,7,8,9,16,63,64,127};unsigned cases=0;
 /* Keep every VOQ continuously backlogged. Even a short budget advances
  * the persistent cursor; no live queue may go eight polls unvisited. */
 for(unsigned b=0;b<sizeof(budgets)/sizeof(*budgets);b++)for(unsigned origin=0;origin<2;origin++) {
  setup(&rx,&owner,&input,origin?255:0);
  for(unsigned q=0;q<8;q++)publish(q,64);
  unsigned baseline[8]={0};
  for(unsigned poll=0;poll<24;poll++) {
   if(!(poll%8))memcpy(baseline,seen_packets,sizeof(baseline));
   unsigned old[8];memcpy(old,seen_packets,sizeof(old));unsigned old_reads=pointer_reads;
   int count=rtl_qm_rx_poll(&rx,&napi,budgets[b]);
   assert(count==(int)budgets[b] && pointer_reads-old_reads==8);
   if(budgets[b]==64)for(unsigned q=0;q<8;q++)assert(seen_packets[q]-old[q]==8);
   if(poll%8==7)for(unsigned q=0;q<8;q++)assert(seen_packets[q]>baseline[q]);
   for(unsigned q=0;q<8;q++)publish(q,64-(prod[q]-cons[q]));
   assert(rx.refill.pending <= (budgets[b]>64 ? budgets[b]-64 : 0));
   assert(!rx.ring_errors && !rx.buffer_errors);
  }
  if(budgets[b]>=8)for(unsigned q=0;q<8;q++)assert(rx.voq_yields[q]);
  cleanup(&rx);cases++;
 }
 /* A continuously busy queue7 cannot starve queue0, while queue7 also
  * has a bounded maximum gap. Preserve FIFO order inside both queues. */
 setup(&rx,&owner,&input,0);publish(7,64);publish(0,64);
 for(unsigned poll=0;poll<20;poll++) {
  unsigned start=sequence_count;
  assert(rtl_qm_rx_poll(&rx,&napi,64)==64);
  for(unsigned i=0;i<64;i++)assert(sequence[start+i]==(i/8%2?0U:7U));
  assert(seen_packets[0]==(poll+1)*32 && seen_packets[7]==(poll+1)*32);
  publish(7,32);publish(0,32);
 }
 cleanup(&rx);cases++;
 /* A single active VOQ borrows all idle share. Ring MMIO/cache work is
  * once per snapshot, not once per eight-packet burst. */
 for(unsigned q=0;q<8;q++) {
  setup(&rx,&owner,&input,0);publish(q,96);
  assert(rtl_qm_rx_poll(&rx,&napi,64)==64);
  assert(seen_packets[q]==64 && rx.voq_yields[q]==8 && ring_syncs[q]==1 && pointer_reads==8);
  assert(rtl_qm_rx_poll(&rx,&napi,64)==32 && seen_packets[q]==96);
  cleanup(&rx);cases++;
 }
 /* A callback appends to a cache line already sampled in this poll.
  * Consume only the original interval, then invalidate it next poll. */
 for(unsigned q=0;q<8;q++)for(unsigned origin=0;origin<2;origin++) {
  setup(&rx,&owner,&input,origin?255:0);publish(q,1);
  inject_queue=q;inject_count=1;
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1 && seen_packets[q]==1 && prod[q]-cons[q]==1);
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1 && seen_packets[q]==2);
  assert(ring_syncs[q]==2 && !rx.refill.pending);cleanup(&rx);cases++;
 }
 setup(&rx,&owner,&input,0);publish(7,16);publish(0,16);
 assert(!rtl_qm_rx_poll(&rx,&napi,0) && !pointer_reads && !sequence_count && rx.next_voq==7);
 assert(rtl_qm_rx_poll(&rx,&napi,1)==1 && sequence[0]==7 && rx.next_voq==6);
 assert(rtl_qm_rx_poll(&rx,&napi,1)==1 && sequence[1]==0 && rx.next_voq==7);
 cleanup(&rx);cases++;
 /* A failed checksum-control read must not claim that hardware validated
  * a packet. An ordinary enabled word still uses the independent parser. */
 const unsigned checksum_states[]={0,BIT(16),BIT(16)|0x1234,~0U};
 for(unsigned i=0;i<sizeof(checksum_states)/sizeof(*checksum_states);i++) {
  setup(&rx,&owner,&input,0);checksum_word=checksum_states[i];publish(7,1);
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
  assert(checksum_validations==((checksum_word!=~0U && (checksum_word&BIT(16)))?1U:0U));
  cleanup(&rx);cases++;
 }
 printf("QM production fairness: %u load/budget/wrap/callback cases; no starving VOQ, no unused-budget stall, one snapshot per poll PASS\n",cases);
}
'''


def run(production, name):
    with tempfile.TemporaryDirectory(prefix="qm-rx-fairness-", dir=ROOT / "artifacts") as temp:
        directory = Path(temp)
        source, binary = directory / "test.c", directory / "test"
        source.write_text(model + production + CASES)
        subprocess.run(["cc", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-function", "-Wno-unused-variable", "-Wno-misleading-indentation",
                        "-fsanitize=address,undefined", "-I", str(DRIVER), "-I",
                        str(ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/include/linux"),
                        str(source), "-o", str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        if name == "production":
            if result.returncode:
                raise SystemExit(result.stdout + result.stderr)
            print(result.stdout.strip())
        else:
            assert result.returncode and "Assertion" in result.stderr, result
            print(f"QM fairness mutation rejected: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = (DRIVER / "rtl9617c-qm.c").read_text()
    production = source[source.index("static void rtl_qm_rx_retire("):
                        source.index("\nssize_t rtl_qm_rx_voq_state(")]
    run(production, "production")
    if args.mutants:
        mutations = {
            "fixed_high_priority_cursor": ("cos = rx->next_voq < RTL_QM_VOQS ? rx->next_voq : RTL_QM_VOQS - 1;",
                                            "cos = RTL_QM_VOQS - 1;"),
            "unbounded_per_queue_burst": ("while (rx->read[cos] != wr && count < limit)",
                                           "while (rx->read[cos] != wr && count < budget)"),
            "discard_unused_budget": ("else if (available & BIT(cos))\n\t\t\trx->voq_yields[cos]++;",
                                       "else if (available & BIT(cos))\n\t\t\trx->voq_yields[cos]++;\n\t\tavailable = 0;"),
            "trust_failed_checksum_control": ("checksum_control != ~0U && (checksum_control & BIT(16))",
                                                "checksum_control & BIT(16)"),
        }
        for name, (before, after) in mutations.items():
            assert production.count(before) == 1, (name, "target drift")
            run(production.replace(before, after), name)


if __name__ == "__main__":
    main()
