#!/usr/bin/env python3
"""Cross-check native FE formats against an external, pinned public GPL SDK.

Usage: python3 scripts/test_fe_sdk_contract.py --sdk /path/to/ca-network-drivers
Reference: https://github.com/jameywine/ca-network-drivers
Commit: 8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0

Only the SDK's actual bitfield types, action converter, mask/CRC implementation
are compiled; kernel logging/table lookup are stubbed. No private board module,
hardware, network fetch or installed firmware is needed. This establishes public
SDK source parity, NOT silicon correctness or a forwarding throughput result.
The SDK stays external and its four inputs are independently SHA256-checked.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
PIN = "8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0"
SDK_FILES = {
    "include/aal_common.h": "6b5b388ed35fd7dd9b91115961da41551b143948e67e50c7f3ae6390817a4b98",
    "aal_common.c": "5348dbc331aebab85231788229b3ddb70cba85437abebb6519ce4fe77907c2db",
    "include/aal_hash.h": "e9771a58e015ac5aa0e844be74e1b225daa8ebd90a63ffba60a35aeb3b6556c8",
    "aal_hash.c": "679ca0a0a8588b3af5a3b04e0ce242636b6d723741a7ef8c5ed04b592035f3ea",
}


def extract_function(source, signature):
    start = source.index(signature)
    return source[start:source.index("\n}", start) + 2]


def compile_source(sdk):
    common_h = sdk["include/aal_common.h"]
    common_c = sdk["aal_common.c"]
    hash_h = sdk["include/aal_hash.h"]
    header = (DRIVER / "rtl9617c-fe-format.h").read_text()
    driver = (DRIVER / "rtl9617c-fe.c").read_text()
    types = common_h[common_h.index("#define HASH_ACTION_GROUP_00"):
                     common_h.index("} __attribute__((packed)) aal_hash_value_t;") +
                     len("} __attribute__((packed)) aal_hash_value_t;")]
    normal = hash_h[hash_h.index("typedef struct hash_action_flow_normal_mode_s"):
                    hash_h.index("}__attribute__((packed)) hash_action_flow_normal_mode_t;") +
                    len("}__attribute__((packed)) hash_action_flow_normal_mode_t;")]
    crc = common_c[common_c.index("static unsigned short crctable_ccitt16"):
                   common_c.index("/* CCITT-CRC32 polynomial:")]
    # SDK reverse_n uses signed 64-bit literal shifts that trip hosted UBSan.
    # Exempt only that unmodified vendor helper's shift instrumentation. The
    # native unsigned implementation and all other reference/tests keep UBSan.
    reverse = crc.index("static TYPE reverse_n(TYPE x, int bits)\n{")
    crc = crc[:reverse] + 'static TYPE reverse_n(TYPE, int) __attribute__((no_sanitize("shift")));\n' + crc[reverse:]
    for signature in ("static uint16_t _ca_xor16(", "static uint32_t _ca_xor32(",
                      "static uint16_t _ca_sum16("):
        crc += "\n" + extract_function(common_c, signature)
    calculate = extract_function(common_c, "int hash_value_calculate(")
    convert = extract_function(sdk["aal_hash.c"], "static void convert_act_flow_nomal_mode(")
    action_fields = re.findall(r"RTL_FE_(\w+),", header.split("enum rtl_fe_action_field {", 1)[1].split("};", 1)[0])[:-1]
    key_fields = re.findall(r"RTL_FE_KEY_(\w+),", header.split("enum rtl_fe_key_field {", 1)[1].split("};", 1)[0])[:-1]
    # Compile the actual runtime route-mask preparation, not a copied test mask.
    prepare = driver[driver.index(" rtl_fe_ipv6_mask(mask);"):
                     driver.index(" ret=rtl_fe_mask_write(&io,63,mask);")]
    source = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-fe-format.h"
#define BIT(n) (1U << (n))
typedef uint64_t ca_uint64_t;
typedef uint32_t ca_uint32_t;
#define AAL_E_OK 0
#define AAL_E_NULLPTR -1
#define AAL_E_INVALID -2
#define AAL_E_OUTRANGE -3
#define AAL_TABLE_HASH_MASK_TBL 0
#define AAL_TABLE_HASHLITE_MASK_TBL 1
#define AAL_DBG_HASH 1
#define AAL_DBG_HASHLITE 2
#define printk(...) ((void)0)
/* Keep the reference functions byte-for-byte unchanged. Suppress only SDK
 * portability warnings; production and test code retain -Werror. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
'''
    source += types + "\n" + normal + "\n" + crc + r'''
static unsigned int ca_aal_debug;
ca_uint32_t hash_key_select[HASH_PROFILE_MAX];
ca_uint32_t hash_tuple_sp_cfg[HASH_PROFILE_MAX];
ca_uint32_t hash_tuple_dp_cfg[HASH_PROFILE_MAX];
ca_uint32_t hash_tuple_sip_cfg[HASH_PROFILE_MAX];
ca_uint32_t hash_tuple_dip_cfg[HASH_PROFILE_MAX];
static aal_hash_mask_t lookup_mask;
static void hash_key_dump(const aal_hash_key_t *key) { (void)key; }
static int aal_entry_get_by_idx(int table, unsigned int index, void *out)
{
 (void)table; (void)index;
 memcpy(out,&lookup_mask,sizeof(lookup_mask));
 return 0;
}
'''
    source += calculate + "\n" + convert + "\n#pragma GCC diagnostic pop\n"
    source += "static void route_mask(unsigned int *mask) {\n" + prepare + "\n}\n"
    source += "static void vendor_action_set(aal_hash_action_t *a, unsigned int field, unsigned int value) {\nswitch(field) {\n"
    for name in action_fields:
        source += f"case RTL_FE_{name}: a->{name.lower()}=value; break;\n"
    source += "default: assert(0); }\n}\n"
    source += "static void vendor_key_set(aal_hash_key_t *k, unsigned int field, unsigned int value) {\nswitch(field) {\n"
    for name in key_fields:
        member = "mdata" if name == "MDATA_BYTE" else name.lower()
        source += f"case RTL_FE_KEY_{name}: k->{member}=value; break;\n"
    source += "default: assert(0); }\n}\n"
    source += TESTS
    return source


TESTS = r'''
_Static_assert(sizeof(aal_hash_key_t)==RTL_FE_KEY_WORDS*4,"SDK key width");
_Static_assert(sizeof(aal_hash_mask_t)==28,"SDK mask width");
_Static_assert(sizeof(hash_action_flow_normal_mode_t)==28,"SDK normal-action width");
static uint32_t random_state=0x9617c;
static uint32_t next_random(void)
{
 random_state^=random_state<<13;
 random_state^=random_state>>17;
 random_state^=random_state<<5;
 return random_state;
}
static void check_action_layout(void)
{
 for(unsigned int field=0;field<RTL_FE_FIELD_COUNT;field++) {
  for(unsigned int bit=0;bit<32;bit++) {
   aal_hash_action_t input={0};
   hash_action_flow_normal_mode_t output={0};
   unsigned int native[8]={0},expected[8]={0};
   unsigned int value=1U<<bit;
   vendor_action_set(&input,field,value);
   convert_act_flow_nomal_mode(&input,&output);
   memcpy(expected,&output,sizeof(output));
   rtl_fe_action_set(native,field,value);
   assert(!memcmp(native,expected,sizeof(native)));
  }
 }
 for(unsigned int vector=0;vector<512;vector++) {
  aal_hash_action_t input={0};
  hash_action_flow_normal_mode_t output={0};
  unsigned int native[8]={0},expected[8]={0};
  for(unsigned int field=0;field<RTL_FE_FIELD_COUNT;field++) {
   unsigned int value=next_random();
   vendor_action_set(&input,field,value);
   rtl_fe_action_set(native,field,value);
  }
  convert_act_flow_nomal_mode(&input,&output);
  memcpy(expected,&output,sizeof(output));
  assert(!memcmp(native,expected,sizeof(native)));
 }
}
static void check_key_layout(void)
{
 for(unsigned int field=0;field<RTL_FE_KEY_FIELD_COUNT;field++) {
  for(unsigned int bit=0;bit<32;bit++) {
   aal_hash_key_t expected={0};
   unsigned int native[23]={0},value=1U<<bit;
   /* MDATA_BYTE is deliberately only the low byte of SDK's 64-bit mdata. */
   if(field==RTL_FE_KEY_MDATA_BYTE)value&=255;
   vendor_key_set(&expected,field,value);
   rtl_fe_key_set(native,field,value);
   assert(!memcmp(native,&expected,sizeof(expected)));
  }
 }
}
static void sdk_hash(aal_hash_key_t *key, const unsigned int mask[8], aal_hash_value_t *value)
{
 memcpy(&lookup_mask,mask,sizeof(lookup_mask));
 assert(!hash_value_calculate(key,&lookup_mask,value));
}
static void check_route_mask(void)
{
 unsigned int words[8];
 aal_hash_mask_t mask;
 route_mask(words);memcpy(&mask,words,sizeof(mask));
 assert(!mask.l4_chksum_zero); /* Conservative zero-checksum CPU fallback. */
 assert(mask.tcp_rdp_ctrl==0x1f8); /* Only FIN/SYN/RST participate. */
 assert(!mask.l3_chksum_err && !mask.ip_fragment_flag && !mask.ip_options);
 assert(!mask.ipv6_doh && !mask.ipv6_rh && !mask.ipv6_hbh);
 assert(mask.ip_da==128 && mask.ip_sa==128);
 assert(!mask.ip_ver && !mask.ip_vld && !mask.ip_protocol);
 assert(!mask.l4_dp_exact_range && !mask.l4_sp_exact_range);
 assert(!mask.pol_id && !mask.lspid && !mask.hkey_id);
 assert(mask.orig_lspid && mask.ctrl_set_id && mask.table_id);
 assert(!mask.vlan_cnt && !mask.inner_vid && !mask.inner_tpid_enc);
 assert(!mask.top_vid && !mask.top_tpid_enc);
 assert(mask.inner_8021p && mask.inner_dei && mask.top_8021p && mask.top_dei);
 assert(!mask.pppoe_session_id && !mask.pppoe_type);
 for(unsigned int flag=0;flag<9;flag++) {
  aal_hash_key_t key={.table_id=1,.tcp_rdp_ctrl=1U<<flag};
  aal_hash_value_t crc={0};
  sdk_hash(&key,words,&crc);
  assert(key.tcp_rdp_ctrl==(flag<3?(1U<<flag):0));
 }
 aal_hash_key_t key={.table_id=1,.ip_ver=1,.l4_chksum_zero=1,.l3_chksum_err=1,.ip_fragment_flag=1,
  .ip_options=1,.ipv6_doh=1,.ipv6_rh=1,.ipv6_hbh=1};
 aal_hash_value_t crc={0};
 sdk_hash(&key,words,&crc);
 assert(key.l4_chksum_zero); /* Retained flag cannot equal an installed zero flag. */
 assert(key.l3_chksum_err && key.ip_fragment_flag && key.ip_options);
 assert(key.ipv6_doh && key.ipv6_rh && key.ipv6_hbh);
}
static void compare_hash(unsigned int *native, aal_hash_key_t *vendor, unsigned int *mask)
{
 aal_hash_value_t value={0};
 unsigned int crc32;
 unsigned short crc16;
 sdk_hash(vendor,mask,&value);
 assert(!memcmp(native,vendor,sizeof(*vendor)));
 rtl_fe_key_crc(native,&crc32,&crc16);
 assert(crc32==value.crc32 && crc16==value.crc16);
}
static void check_route_keys(void)
{
 unsigned int mask[8];route_mask(mask);
 for(unsigned int vector=0;vector<1024;vector++) {
  unsigned int native[23],count=vector%3;
  struct rtl_fe_ipv6_key key={.source_port=next_random(),.destination_port=next_random(),
   .llid=next_random()&511,.protocol=vector&2?6:17,.ingress=vector%8,
   .profile=vector%4,.mask=63};
  struct rtl_fe_vlan vlan[2]={{0}};
  for(unsigned int n=0;n<4;n++) {
   key.source[n]=next_random();key.destination[n]=next_random();
  }
  aal_hash_key_t vendor={.table_id=1,.hkey_id=key.mask,.ctrl_set_id=key.profile,
   .lspid=key.ingress,.orig_lspid=key.ingress,.pol_id=key.llid,
   .ip_vld=1,.ip_ver=vector&1,.ip_protocol=key.protocol,
   .ip_sa_0=key.source[3],.ip_da_0=key.destination[3],
   .l4_sp_exact_range=key.source_port,.l4_dp_exact_range=key.destination_port,
   .tcp_rdp_ctrl=0x1f8,.ip_ttl=47,.ip_dscp=37,.ip_ecn=3};
  if(vector&1) {
   rtl_fe_ipv6_key(native,&key);
   vendor.ip_sa_1=key.source[2];vendor.ip_sa_2=key.source[1];vendor.ip_sa_3=key.source[0];
   vendor.ip_da_1=key.destination[2];vendor.ip_da_2=key.destination[1];vendor.ip_da_3=key.destination[0];
  } else {
   struct rtl_fe_ipv4_key key4={.source=key.source[3],.destination=key.destination[3],
    .source_port=key.source_port,.destination_port=key.destination_port,.llid=key.llid,
    .protocol=key.protocol,.ingress=key.ingress,.profile=key.profile,.mask=key.mask};
   rtl_fe_ipv4_key(native,&key4);
  }
  for(unsigned int n=0;n<count;n++)vlan[n]=(struct rtl_fe_vlan){
   .vid=next_random()&4095,.tpid=1+(next_random()%2),.priority=vector%8,.dei=1};
  rtl_fe_vlan_key(native,vlan,count);
  vendor.vlan_cnt=count;
  if(count) {
   vendor.top_vid=vlan[0].vid;vendor.top_tpid_enc=vlan[0].tpid;
   vendor.top_8021p=vlan[0].priority;vendor.top_dei=1;
  }
  if(count>1) {
   vendor.inner_vid=vlan[1].vid;vendor.inner_tpid_enc=vlan[1].tpid;
   vendor.inner_8021p=vlan[1].priority;vendor.inner_dei=1;
  }
  if(vector&4) {
   unsigned int session=next_random()&65535;
   rtl_fe_key_set(native,RTL_FE_KEY_PPPOE_SESSION_ID,session);
   rtl_fe_key_set(native,RTL_FE_KEY_PPPOE_TYPE,2);
   vendor.pppoe_session_id=session;vendor.pppoe_type=2;
  }
  rtl_fe_key_set(native,RTL_FE_KEY_ORIG_LSPID,0);
  rtl_fe_key_set(native,RTL_FE_KEY_CTRL_SET_ID,0);
  rtl_fe_key_set(native,RTL_FE_KEY_TABLE_ID,0);
  compare_hash(native,&vendor,mask);
 }
}
static void check_bridge_keys(void)
{
 unsigned int mask[8];rtl_fe_bridge_mask(mask);
 for(unsigned int vector=0;vector<256;vector++) {
  unsigned int native[23];unsigned char source[6],destination[6];
  unsigned int ingress=vector%8,llid=next_random()&511,protocol=vector&1?0x800:0x86dd;
  for(unsigned int n=0;n<6;n++){source[n]=next_random();destination[n]=next_random();}
  aal_hash_key_t vendor={.table_id=1,.hkey_id=61,.lspid=ingress,.pol_id=llid,.ethertype=protocol,
   .mac_sa_5=source[0],.mac_sa_4=source[1],.mac_sa_3=source[2],.mac_sa_2=source[3],.mac_sa_1=source[4],.mac_sa_0=source[5],
   .mac_da_5=destination[0],.mac_da_4=destination[1],.mac_da_3=destination[2],.mac_da_2=destination[3],.mac_da_1=destination[4],.mac_da_0=destination[5]};
  rtl_fe_bridge_key(native,source,destination,protocol,ingress,llid,61);
  rtl_fe_key_set(native,RTL_FE_KEY_TABLE_ID,0);
  compare_hash(native,&vendor,mask);
 }
}
int main(void)
{
 check_action_layout();check_key_layout();check_route_mask();check_route_keys();check_bridge_keys();
 printf("Public SDK source parity: %u action fields x32 single-bit +512 random vectors; "
  "%u key fields x32 single-bit; 1024 IPv4/IPv6 TCP/UDP VLAN/QinQ/PPPoE keys +256 L2 keys; "
  "masked-key, CRC16/32, exception and TCP flag contracts PASS (no hardware test)\n",
  RTL_FE_FIELD_COUNT,RTL_FE_KEY_FIELD_COUNT);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path, help="external ca-network-drivers checkout")
    args = parser.parse_args()
    base = args.sdk / "ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c"
    sources = {}
    for name, expected in SDK_FILES.items():
        data = (base / name).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise SystemExit(f"SDK pin mismatch: {name}: {actual}; expected {expected} ({PIN})")
        sources[name] = data.decode()
    with tempfile.TemporaryDirectory(prefix="fe-sdk-contract-") as temporary:
        directory = Path(temporary)
        source = directory / "sdk_contract.c"
        binary = directory / "sdk_contract"
        source.write_text(compile_source(sources))
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                        "-fno-strict-aliasing", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I", str(DRIVER), str(source), "-o", str(binary)], check=True)
        environment = dict(os.environ)
        environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
        subprocess.run([str(binary)], check=True, env=environment)
    print(f"Reference: jameywine/ca-network-drivers@{PIN}; all four SHA256 inputs verified")


if __name__ == "__main__":
    main()
