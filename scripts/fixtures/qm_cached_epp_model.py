common=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef unsigned long long u64;typedef uintptr_t dma_addr_t;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(mask,x) (((x)&(mask))>>__builtin_ctz(mask))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(x) (x)
#define lower_32_bits(x) ((u32)(x))
#define dma_rmb() ((void)0)
#define mb() ((void)0)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(x) (x)
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_PPP_SES 0x8864
#define IPPROTO_UDP 17
#define CHECKSUM_UNNECESSARY 1
#define DMA_FROM_DEVICE 2
#define NAPI_POLL_WEIGHT 64
#define L1_CACHE_BYTES 64
#define round_down(x,a) ((x)&~((a)-1))
#define round_up(x,a) (((x)+(a)-1)&~((a)-1))
#define prefetch(p) ((void)(p))
#define RTL_QM_RING_BYTES 1024
#define RTL_QM_COMMAND_BYTES 8
#define RTL_QM_VOQS 8
#include "rtl9617c-qm-layout.h"
#define RTL_QM_MEMORY_BYTES (8192+512*2048)
#define EQ_ID 4
#define EPP_WRITE 0x7000
#define EPP_READ 0x7100
#include "rtl9617c-qm-refill.h"
struct net_device {bool running;struct {u64 rx_errors,rx_dropped,rx_packets,rx_bytes;} stats;};
struct napi_struct {struct net_device *dev;};
struct sk_buff {u8 storage[128],*data;unsigned len,priority,protocol,ip_summed;struct net_device *dev;};
struct rtl9617c_ni_endpoint {void (*receive)(struct rtl9617c_ni_endpoint *,struct napi_struct *,struct sk_buff *,unsigned);};
struct rtl_qm_rx {
 void *ni,*ring_memory,*memory,*device;dma_addr_t memory_dma,ring_dma;unsigned read[8];
 u32 last_address,last_size,last_header[2],trace[32][7];unsigned trace_count;
 struct rtl_qm_refill refill;struct rtl9617c_ni_endpoint *pon;struct net_device *lan[5];bool profile;
 u64 host_poll_ns,host_polls,voq_packets[8],poll_budget_hits;
 bool rx_prefetch,pppoe_rx_checksum;
};
static struct rtl_qm_rx *active;
static unsigned producer,consumer,drops,kind,delivered,injected;
static bool seen[129];
static u32 get_unaligned_le32(const void *p){u32 v;memcpy(&v,p,4);return v;}
static u32 get_unaligned_be32(const void *p){return __builtin_bswap32(get_unaligned_le32(p));}
static u16 get_unaligned_be16(const void *p){u16 v;memcpy(&v,p,2);return __builtin_bswap16(v);}
static void put(u32 v,void *p){memcpy(p,&v,4);}
#define sysfs_emit(buf,fmt,...) snprintf((buf),4096,(fmt),__VA_ARGS__)
static u64 ktime_get_ns(void){static u64 t;return ++t;}
static u32 readl(void *p){unsigned r=(u8 *)p-(u8 *)active->ni;
 if(r==0x3218)return 0;if(r==0x659c)return producer!=consumer;
 if(r>=EPP_WRITE&&r<EPP_WRITE+32)return r==EPP_WRITE?(producer%128)*8:0;
 assert(false);return 0;}
static void writel(u32 v,void *p){unsigned r=(u8 *)p-(u8 *)active->ni;
 if(r==EPP_READ){consumer+=((v-(consumer%128)*8)&1023)/8;assert(consumer<=producer);}
 else assert(r>EPP_READ&&r<EPP_READ+32&&v==0);
}
static void dma_sync_single_for_cpu(void *d,dma_addr_t a,unsigned n,int direction){(void)d;
 if(a>=active->ring_dma&&a<active->ring_dma+8192){assert(n&&!(a%64)&&!(n%64)&&a+n<=active->ring_dma+8192&&direction==2);return;}
 assert(n==2048&&direction==2);}
static inline void dma_sync_single_for_device(void *d,dma_addr_t a,unsigned n,int direction){dma_sync_single_for_cpu(d,a,n,direction);}
static int rtl_qm_try_push(void *context,unsigned address,unsigned eq){struct rtl_qm_rx *rx=context;
 unsigned id=(address-(u32)rx->memory_dma-8192)/2048;
 assert(eq==4&&consumer>id);return 0;}
static bool rtl_rx_checksum_valid(u32 c,const void *p,unsigned n){(void)c;(void)p;(void)n;return false;}
static struct sk_buff *napi_alloc_skb(struct napi_struct *n,unsigned length){(void)n;assert(length==64);struct sk_buff *s=calloc(1,sizeof(*s));assert(s);s->data=s->storage;return s;}
static void *skb_put(struct sk_buff *s,unsigned n){void *p=s->data+s->len;s->len+=n;return p;}
static void dev_kfree_skb_any(struct sk_buff *s){free(s);}
static bool netif_running(struct net_device *d){return d->running;}
static unsigned eth_type_trans(struct sk_buff *s,struct net_device *d){(void)d;s->data+=14;s->len-=14;return ETH_P_IP;}
static void packet_bytes(unsigned id,u8 *b){memset(b,0xa5,64);b[0]=2;b[12]=8;b[13]=0;b[14]=0x45;b[23]=17;b[36]=18081>>8;b[37]=18081&255;put(__builtin_bswap32(id),b+42);}
static void enqueue(unsigned id){
 if(producer-consumer==128){drops++;return;}
 unsigned offset=8192+id*2048,header=kind==1?16:8;u32 h0=kind==2?5U<<18:0,h1=64U<<15|(kind==2?7U<<9:0);
 put(__builtin_bswap32(h0),active->memory+offset+RTL_QM_HEADROOM);put(__builtin_bswap32(h1),active->memory+offset+RTL_QM_HEADROOM+4);
 packet_bytes(id,active->memory+offset+RTL_QM_HEADROOM+header);
 void *entry=active->ring_memory+(producer%128)*8;
 put(((u32)active->memory_dma+offset)|0x54,entry);put(kind==1?1U<<14|80:0,entry+4);producer++;
}
static void received(struct sk_buff *s){unsigned skip=kind==0?14:0;u8 expected[64];unsigned id=get_unaligned_be32(s->data+42-skip);
 assert(id<129&&!seen[id]);seen[id]=true;packet_bytes(id,expected);assert(s->len==64-skip&&!memcmp(s->data,expected+skip,s->len));delivered++;
 if(!injected++){for(unsigned i=64;i<129;i++)enqueue(i);}free(s);
}
static void napi_gro_receive(struct napi_struct *n,struct sk_buff *s){(void)n;assert(kind==0);received(s);}
static void pon_receive(struct rtl9617c_ni_endpoint *e,struct napi_struct *n,struct sk_buff *s,unsigned metadata){(void)e;(void)n;assert(kind==2&&metadata==(7|5<<8));received(s);}
'''
