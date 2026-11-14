#!/usr/bin/env python3
"""Validate native L2 formats against external, pinned vendor GPL sources.

Usage: test_l2_sdk_contract.py --sdk /path/to/ca-network-drivers \
    --registers /path/to/rtl8277c_registers.h

Compiles the actual generated silicon register unions, SDK UC FDB overlay,
MAC encoder, and PONCLE ternary conversion. No SDK code is copied into the
product. This is source-contract parity, not a hardware forwarding result.
The independent transaction/fault model is test_l2_table_transactions.py.
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
SDK_PIN = "8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0"
REG_PIN = "5090fbcb6ba743dd7b1314811ef557bad0460147"
REG_HASH = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"
SDK_FILES = {
    "../cortina-api/vlan.c": "d819b6621f11054df8a92bb323affcbb741e90dcfad38af5bcefa0f34dc33b20",
    "include/aal_fdb.h": "e8b0cdfd5ec7a3dfea844375abacb4813d55ba063edfb678c36172b925631ae4",
    "aal_fdb.c": "b578ced837bf926a2f440b25a775e74935413a983cb8b27dbecb46ead35a8683",
    "include/aal_mcast.h": "f6dc118c698b91fed29d920ced7c84501a02d13a416316c67c58268c3a0b596d",
    "include/aal_port.h": "190e4c0c2ac7e99515162fac8775fb33c5ee605423d3809b09bda85708c99f7e",
    "include/aal_arb.h": "261710e2067c4196a2eb24cc39e9d6887f3023a4ce0e5012d477832c0d50ec4e",
    "include/aal_l2_qos.h": "d7c1735cc4afc09fc1036a239a4c627f337dde52798a9fc242378a66057f9720",
    "include/aal_l2_vlan.h": "1e7a61daeb29fea9b1b36febd1563f6494de2ae01428b587ab5a7406e2dec282",
    "include/aal_l3_cls.h": "dfc3c36383187301c5df340dec8e609e860fbad5b42e191b6aba16fe6d253fc0",
    "include/aal_l3fe.h": "8338ff3845608c7740b1acf3ec258bf4c927187135e5a0f1f616c5c6fc3f1fd5",
    "include/aal_l2_specpkt.h": "8e6d5fbdae4ccaab2d8d7950594e2ddd560cd2ec9d81bb8c88450c5ad168ccf1",
    "aal_l2_specpkt.c": "fc9ad8debd4fe61b6e5b03f5527261a49fb6037aa78bdece2cd76d622f6df6c8",
    "aal_l2_classification.c": "1319689d280d03ce6a2bfb60d70a616e06645d10111185df2ce074c0a9cd13b6",
    "include/aal_l2_classification.h": "346e7b81db21b222b39c54c38341943ef9b4fa5af5dc946a2781ebb4de373ae1",
}

# Independent register names/field names. Offsets, widths and masks are taken
# from the real generated unions, never from the implementation under test.
FIELDS = {
    "L2FE_PP_IPPB_DATA": "IPPB_SOURCE:lspid",
    "L2FE_PP_SPKTP_DATA": "SPECIAL_PRIORITY_TYPE:encode",
    "L2FE_PP_ILPB_DATA0": """INGRESS_FILTER:ing_fltr_ena DEFAULT_PREMARK:dflt_premark
        COLOR_SOURCE:color_src_sel DEFAULT_COS:default_cos COS_MARK:cos_control_bm
        COS_MODE:cos_mode_sel DEFAULT_DSCP:default_dscp DSCP_MARK:dscp_mark_control_bm
        DSCP_MODE:dscp_mode_sel DSCP_MARKDOWN:dscp_markdown_en DEFAULT_PRIORITY:default_802_1p
        INNER_PRIORITY_MODE:inner_802_1p_mode_sel PRIORITY_MARK_LOW:802_1p_mark_control_bm""",
    "L2FE_PP_ILPB_DATA1": """CLASSIFIER_LENGTH:cls_length CLASSIFIER_START:cls_start
        CLASSIFIER_ENABLE:igr_cls_lookup_en SPECIAL_PROFILE:spcl_pkt_idx
        LOOP_ENABLE:loop_enable SA_MOVE_DISABLE_FORWARD:sa_move_dis_fwd
        STATION_MOVE_ENABLE:station_move_en PRIORITY_MARK_HIGH:802_1p_mark_control_bm
        CHANGE_PRIORITY_ON_POP:change_1p_if_pop TOP_PRIORITY_MODE:top_802_1p_mode_sel
        FLOW_ID_SELECT:flowid_sel_bm DA_SA_SWAP:da_sa_swap_en""",
    "L2FE_PP_ILPB_DATA2": """STP:stp_mode INNER_C_TPID_ENABLE:inner_c_tpid_enable
        INNER_S_TPID_ENABLE:inner_s_tpid_enable TOP_C_TPID_ENABLE:top_c_tpid_enable
        TOP_S_TPID_ENABLE:top_s_tpid_enable C_TPID_MATCH:c_tpid_match S_TPID_MATCH:s_tpid_match
        DROP_DOUBLE_TAG:drop_doubletagged_packet DROP_PRIORITY_TAG:drop_prytagged_packet
        DROP_UNTAGGED:drop_untagged_packet DROP_C_TAG:drop_ctag_packet DROP_S_TAG:drop_stag_packet
        DROP_SINGLE_TAG:drop_singletagged_packet NON_INNER_TAG_COMMAND:default_noninnertag_cmd
        INNER_VLAN_COMMAND:inner_vlan_cmd INNER_VID_SELECT:inner_vid_sel_bm
        UNTAG_COMMAND:default_untag_cmd TOP_VLAN_COMMAND:default_top_vlan_cmd
        OTHER_TPID_MATCH:other_tpid_match""",
    "L2FE_PP_ILPB_DATA3": """VLAN_COMMAND_SELECT:vlan_cmd_sel_bm SC_IND:sc_ind
        DEFAULT_VID:default_vlanid SA_MISS_FORWARD:sa_miss_fwd SA_LIMIT_DROP:sa_lmt_excd_drop""",
    "L2FE_PP_ILPB_DATA4": "WAN:wan_ind CPU_PORT:cp_port",
    "L2FE_PLC_ELPB_DATA0": """VLAN_AWARE:egr_vlan_aware_mode STP_FORWARD:egr_port_stp_status
        VLAN_LOOKUP:egr_ve_srch_en WAN:egr_dest_wan CLASSIFIER_LENGTH:egr_cls_length
        CLASSIFIER_START:egr_cls_start CLASSIFIER_ENABLE:egr_cls_lookup_en
        CLASSIFIER_FLOW_SELECT:egr_cls_flowid_sel CLASSIFIER_COS_SELECT:egr_cls_cos_sel
        DSCP_MARK:dscp_mark_control_bm DSCP_MODE:dscp_mode_sel DSCP_CONTROL:dscp_ctrl_sel
        DSCP_MARKDOWN:dscp_markdown_en INNER_PRIORITY_MODE:inner_802_1p_mode_sel
        PRIORITY_MARK_LOW:802_1p_mark_control_bm""",
    "L2FE_PLC_ELPB_DATA1": """PRIORITY_MARK_HIGH:802_1p_mark_control_bm
        CHANGE_PRIORITY_ON_POP:change_1p_if_pop TOP_PRIORITY_MODE:top_802_1p_mode_sel
        PRIORITY_CONTROL:802_1p_ctrl_sel USE_TX_VLAN_ACL:use_tx_vlan_lkup_acl""",
    "L2FE_PLA_SPB_DATA": """NO_EDIT:pkt_no_edit KEEP_TIMESTAMP:keep_ts
        BYPASS_SA_CHECK:bypass_sa_lrn_chk LIMIT_FORWARD_PERMIT:limit_fwd_permit
        LEARN_DISABLE:learn_dis GROUP_ENABLE:grpid_en FLOW_ID:flowid FLOW_ENABLE:flow_en
        RATE_LIMIT_BYPASS:rate_limit_bypass COS:cos DESTINATION:ldpid SPECIAL_FORWARD:spcl_fwd
        NO_DROP:pkt_no_drop COLLISION_FORWARD_PERMIT:hash_cllsn_fwd_permit""",
    "L2FE_PLE_DFT_FWD_DATA": "DENY:deny GROUP:mc_group_id REDIRECT:redir_en GROUP_VALID:mc_group_id_valid",
    "L2FE_PLE_MMSHP_CHK_ID_MAP_DATA": "MEMBERSHIP_CHECK_ID:mmshp_chk_id_map_chk_id",
    "L2FE_VE_LAN_VL_IDX_DATA": "VLAN_INDEX_VALID:lan_vl_idx_entry_vld VLAN_INDEX_FIB:lan_vl_idx_fib_idx",
    "L2FE_VE_VL_FIB_DATA0": "VLAN_FIB_UNTAG:wan_svl_fib_egress_top_untag_bm VLAN_FIB_MEMBERS:wan_svl_fib_membership_bm",
    "L2FE_VE_VL_FIB_DATA1": "VLAN_FIB_GROUP:wan_svl_fib_vl_group_id",
    "L2FE_ARB_MC_FIB_TBL_DATA0": """C_VLAN_COMMAND:c_vlan_cmd C_VID:c_vid
        C_TPID_COMMAND:c_tpid_cmd C_TPID_SELECT:c_tpid_sel C_PRIORITY_COMMAND:c_dot1p_cmd
        C_PRIORITY:c_dot1p C_DEI_COMMAND:c_dei_cmd C_DEI:c_dei POLICER_ID:pol_id""",
    "L2FE_ARB_MC_FIB_TBL_DATA1": """S_VLAN_COMMAND:s_vlan_cmd S_VID:s_vid
        S_TPID_COMMAND:s_tpid_cmd S_TPID_SELECT:s_tpid_sel S_PRIORITY_COMMAND:dot1p_cmd
        S_PRIORITY:dot1p S_DEI_COMMAND:dei_cmd S_DEI:dei DESTINATION:ldpid
        COS_COMMAND:cos_cmd WAN_DESTINATION:wan_dst""",
    "L2FE_ARB_MC_FIB_TBL_DATA2": """PERMIT_SOURCE_PORT:permit_spid_en
        SOURCE_MAC_COMMAND:mac_sa_cmd SOURCE_MAC_SELECT:mac_sa_sel COS:cos
        TTL_ZERO_CONTROL:ip_ttl_zero_fwd_ctrl TTL_DECREMENT:ip_ttl_dec_cmd
        KEEP_ORIGINAL_SOURCE_PORT:keep_o_lspid""",
    "L2FE_ARB_REDIR_LDPID_CONFIG_TBL_DATA": """COS_VALID:rdir_cos_vld COS:rdir_cos
        DESTINATION:rdir_ldpid ENABLE:rdir_en WAN:rdir_wan_dst""",
}

TABLES = {
    "ILPB": ("L2FE_PP_ILPB", 5),
    "ELPB": ("L2FE_PLC_ELPB", 2),
    "SPB": ("L2FE_PLA_SPB", 1),
    "DFT_FWD": ("L2FE_PLE_DFT_FWD", 1),
    "MEMBERSHIP_ID": ("L2FE_PLE_MMSHP_CHK_ID_MAP", 1),
    "PORT_MEMBERSHIP": ("L2FE_PLE_PORT_MMSHP_CHK", 2),
    "VLAN_LAN_INDEX": ("L2FE_VE_LAN_VL_IDX", 1),
    "VLAN_FIB": ("L2FE_VE_VL_FIB", 2),
    "MC_FIB": ("L2FE_ARB_MC_FIB_TBL", 3),
    "MC_VECTOR": ("NI_HV_MCE_INDX_LKUP", 2),
    "REDIR_LDPID": ("L2FE_ARB_REDIR_LDPID_CONFIG_TBL", 1),
    "REDIR_DROP": ("L2FE_ARB_REDIR_DROP_SRC_CONFIG_TBL", 1),
    "CF_KEY": ("L2FE_PONCLE_KEY", 3),
    "CF_FIB": ("L2FE_PONCLE_FIB", 3),
    "IPPB": ("L2FE_PP_IPPB", 1),
    "SPECIAL_PRIORITY": ("L2FE_PP_SPKTP", 1),
}


def checked(path, digest):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit(f"Pinned source digest mismatch: {path}")
    return data.decode()


def declaration(header, name):
    start = re.search(r"^#define " + name + r"\s+0x", header, re.M).start()
    end = header.index("#endif /* !__ASSEMBLER__ */", start)
    return header[start:end] + "#endif /* !__ASSEMBLER__ */\n"


def typedef(source, name):
    end = re.search(r"}\s*(?:__attribute__\(\(packed\)\)\s*)?" + re.escape(name) + r";", source).end()
    start = source.rfind("typedef ", 0, end)
    return source[start:end]


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index("\n}", start) + 2]


def field_names(register, item):
    native, vendor = item.split(":")
    for needle, native_prefix, vendor_prefix in (
        ("_ILPB_", "ILPB_", "ilpb_"), ("_ELPB_", "ELPB_", "elpb_"),
        ("_SPB_", "SPB_", "spb_"), ("_DFT_FWD_", "DFT_", "dft_fwd_"),
        ("_MC_FIB_", "MC_", ""), ("_REDIR_LDPID_", "REDIR_", ""),
    ):
        if needle in register:
            return native_prefix + native, vendor_prefix + vendor
    return native, vendor


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-l2-table.h"
#include "rtl9617c-fe-pipeline.h"
typedef uint32_t ca_uint32_t;
typedef uint8_t ca_uint8_t;
typedef uint32_t ca_uint32;
typedef uint8_t ca_uint8;
typedef int32_t ca_int32;
typedef unsigned int ca_device_id_t;
typedef int ca_status_t;
typedef unsigned char ca_mac_addr_t[6];
#define CA_E_OK 0
#define CA_E_BUSY (-EBUSY)
#define CA_E_PARAM (-EINVAL)
#define CA_E_TIMEOUT (-ETIMEDOUT)
#define CA_IN
#define BIT(n) (1U << (n))
#define OFFSET(reg) ((reg)-0xf4300000U)
'''


def compile_source(registers, sdk):
    names = set(FIELDS)
    names.update({"L2FE_L2E_CTRL", "L2FE_L2E_FDB_ACCESS", "L2FE_L2E_FDB_CMD_RETURN"})
    names.update({"L2FE_PLC_VLAN_MODE_CTRL", "L2FE_PLC_HASH_CTRL"})
    names.update({"L2FE_L2E_PORT_MAC_CNT_LMT_ACCESS", "L2FE_L2E_PORT_MAC_CNT_LMT_DATA"})
    names.update({"L3FE_CLS_KEY_TBL_ACCESS", "L3FE_CLS_KEY_TBL_DATA10"})
    names.update({"L3FE_STG0_LPB_TBL_MID_1", "L3FE_STG0_LPB_TBL_MID_2"})
    names.update({"L2FE_PP_RSV_GROUP_MAC_LOW", "L2FE_PP_RSV_GROUP_MAC_HI",
                  "L2FE_PP_RSV_GROUP_ENABLE_LOW", "L2FE_PP_RSV_GROUP_ENABLE_HI"})
    names.update(f"L2FE_L2E_FDB_DATA{i}" for i in range(4))
    names.update(f"L2FE_L2E_FDB_CPU_CMD_WORD{i}" for i in range(5))
    names.update(f"L2FE_PP_TPID_CMP_{kind}" for kind in ("S", "C", "O", "USER"))
    for prefix, words in TABLES.values():
        names.add(prefix + "_ACCESS")
        if words == 1:
            names.add(prefix + "_DATA")
        else:
            names.update(f"{prefix}_DATA{i}" for i in range(words))
    source = COMMON + "\n".join(declaration(registers, name) for name in sorted(names))
    source += "\n" + typedef(sdk["include/aal_fdb.h"], "aal_fdb_data0_t")
    source += "\n" + typedef(sdk["include/aal_fdb.h"], "__fdb_tbl_opcode_t")
    source += "\n" + typedef(sdk["include/aal_port.h"], "aal_stp_state_t")
    source += "\n" + typedef(sdk["include/aal_port.h"], "aal_vlan_tpid_index_t")
    # Compile the unchanged vendor decoder. Its bits1..3 are fixed TPIDs;
    # only bit0 refers to the per-class user comparator. This is independent
    # of the observed reset CSR values, which all duplicate 8100 on TYFZA1.
    source += "\n" + function(sdk["../cortina-api/vlan.c"], "void __l2_vlan_tpid_bmp2list(")
    native_hw = (DRIVER / "rtl9617c-fe-switch-hw.h").read_text()
    for name in ("FE_SW_TPID_STANDARD", "FE_SW_TPID_USER", "FE_SW_TPID_ALL"):
        source += "\n" + re.search(r"^#define " + name + r"[^\n]+", native_hw, re.M).group()
    source += "\n" + typedef(sdk["include/aal_l2_vlan.h"], "aal_l2_vlan_mode_t")
    source += "\n" + typedef(sdk["include/aal_arb.h"], "aal_ple_nonkwn_type_t")
    source += "\n" + typedef(sdk["include/aal_l3_cls.h"], "cls_fib_mod_0_t")
    source += "\n" + typedef(sdk["include/aal_l3_cls.h"], "l3_cls_fib_tbl_entry_t")
    source += "\n" + typedef(sdk["include/aal_l3fe.h"], "L3FE_STG0_LPB_TBL_MID_t")
    source += "\n" + typedef(sdk["include/aal_l2_specpkt.h"], "aal_l2_specpkt_type_t")
    for name in ("aal_fdb_cpu_cmd_word0_t", "aal_fdb_cpu_cmd_word1_t", "aal_fdb_cpu_cmd_word4_msk_t"):
        source += "\n" + typedef(sdk["include/aal_fdb.h"], name)
    source += "\n" + typedef(sdk["include/aal_l2_classification.h"], "aal_l2_cf_action_fwd_act_t")
    source += "\n" + typedef(sdk["include/aal_l2_classification.h"], "aal_l2_cf_patten_pkt_type_t")
    # Actual SDK MAC conversion has signed left shifts in its uint8 promotions;
    # exempt ONLY that unchanged external reference, as in the FE CRC oracle.
    source += r'''
void __aal_mac_2_fdb_data(L2FE_L2E_FDB_DATA3_t *, L2FE_L2E_FDB_DATA2_t *,
    L2FE_L2E_FDB_DATA1_t *, ca_mac_addr_t) __attribute__((no_sanitize("shift")));
'''
    source += function(sdk["aal_fdb.c"], "void __aal_mac_2_fdb_data(")
    for name in ("MCE_INDX_TBL_ENTRY_MAX", "ARB_FIB_TBL_ENTRY_MAX", "MCFIB_COS_CMD_EN", "MCFIB_COS_CMD_DIS"):
        source += "\n" + re.search(r"^#define " + name + r"[^\n]+", sdk["include/aal_mcast.h"], re.M).group()
    for name in ("AAL_DSCP_MODE_RX_DSCP", "AAL_DOT1P_MODE_RX_DOT1P_OR_PORT_DEF"):
        source += "\n" + re.search(r"^#define " + name + r"[^\n]+", sdk["include/aal_l2_qos.h"], re.M).group()
    for name in ("AAL_FDB_TABLE_SIZE", "AAL_FDB_OVERFLOW_TABLE_SIZE", "AAL_FDB_MAX_NUM"):
        source += "\n" + re.search(r"^#define " + name + r"[^\n]+", sdk["aal_fdb.c"], re.M).group()
    for name in ("CA_AAL_L2E_CMD_MODE", "CA_AAL_L2E_INDIRECT_MODE", "CA_AAL_L2E_LMT_ACCESS",
                 "CA_AAL_L2E_CNT_INC", "CA_AAL_L2E_CNT_DEC", "CA_AAL_FDB_TBL_OP_TIMEOUT",
                 "CA_AAL_L3E_CNT_LMT_SUCCESS", "CA_AAL_L3E_CNT_LMT_FAIL"):
        source += "\n" + re.search(r"^#define " + name + r"[^\n]+", sdk["include/aal_fdb.h"], re.M).group()
    for name in ("L3_CLS_PROFILE_MAX", "L3_CLS_KEY_TBL_ENTRY_MAX"):
        source += "\n" + re.search(r"^#define " + name + r"[^\n]+", sdk["include/aal_l3_cls.h"], re.M).group()
    source += "\n" + re.search(r"^#define T2_CTRL_BYPASS[^\n]+", sdk["include/aal_l3fe.h"], re.M).group()
    source += "\nstatic void check_fields(void) {\nunsigned int tested=0;\n"
    field_set = set()
    for register, fields in FIELDS.items():
        word_match = re.search(r"DATA(\d+)$", register)
        word = int(word_match.group(1)) if word_match else 0
        for item in fields.split():
            native, vendor = field_names(register, item)
            field_set.add(native)
            source += f'''
 {{
  {register}_t reg;
  for(unsigned int bit=0;bit<32;bit++) {{
   unsigned int words[5],expected[5],value=1U<<bit,got;
   for(unsigned int j=0;j<5;j++) words[j]=expected[j]=0x5aa59617U ^ (j*0x03259U);
   reg.wrd=expected[{word}];reg.bf.{vendor}=value;
   int valid=reg.bf.{vendor}==value;
   if(RTL_L2_{native}==RTL_L2_ILPB_SPECIAL_PROFILE && value>=8) valid=0;
   int ret=rtl_l2_field_set(words,RTL_L2_{native},value);
   if(valid) {{
    assert(!ret);expected[{word}]=reg.wrd;
    assert(!rtl_l2_field_get(words,RTL_L2_{native},&got) && got==value);
   }} else assert(ret==-EINVAL);
   assert(!memcmp(words,expected,sizeof(words)));
  }}
  tested++;
 }}
'''
    product = (DRIVER / "rtl9617c-l2-format.h").read_text()
    actual_fields = set(re.findall(r"^\s*X\((\w+),", product, re.M))
    if actual_fields != field_set:
        raise SystemExit(f"Oracle must cover EVERY native field: missing={actual_fields-field_set}; extra={field_set-actual_fields}")
    source += 'assert(tested==RTL_L2_FIELD_COUNT);}\nstatic void check_tables(void) {\n'
    for native, (prefix, words) in TABLES.items():
        data0 = prefix + ("_DATA" if words == 1 else "_DATA0")
        # This is a deliberately narrower API than the five-bit physical
        # address. The actual SDK getter below rejects priority index31.
        count = "access.bf.addr" if native == "SPECIAL_PRIORITY" else "access.bf.addr+1U"
        source += f'''
 {{
  struct rtl_l2_table_layout native;
  {prefix}_ACCESS_t access={{.wrd=~0U}};
  assert(!rtl_l2_table_layout(RTL_L2_TBL_{native},&native));
  assert(native.access==OFFSET({prefix}_ACCESS) && native.data0==OFFSET({data0}));
  assert(native.entries=={count} && native.words=={words});
  access.wrd=0;access.bf.access=1;assert(access.wrd==RTL_L2_ACCESS_BUSY);
  access.wrd=0;access.bf.rbw=1;assert(access.wrd==RTL_L2_ACCESS_WRITE);
 }}
'''
        for word in range(words):
            reg = prefix + ("_DATA" if words == 1 else f"_DATA{word}")
            source += f"assert({reg}=={data0}-{word}*4);\n"
    source += "}\n" + CF_REFERENCE
    source += function(sdk["aal_l2_classification.c"], "ca_status_t __aal_l2_cf_key_write(")
    source += LIMIT_REFERENCE
    source += function(sdk["aal_fdb.c"], "ca_status_t __aal_l2e_cpu_op_mode(")
    source += function(sdk["aal_fdb.c"], "ca_status_t __aal_port_mac_lmt(")
    source += "\n#pragma GCC diagnostic pop\n"
    source += PRIORITY_REFERENCE
    source += function(sdk["aal_l2_specpkt.c"], "ca_status_t aal_l2_specpkt_pri_get(")
    source += "\n#pragma GCC diagnostic pop\n"
    source += TESTS
    return source


CF_REFERENCE = r'''
typedef struct {
 L2FE_PONCLE_KEY_DATA0_t key_data0;
 L2FE_PONCLE_KEY_DATA1_t key_data1;
 L2FE_PONCLE_KEY_DATA2_t key_data2;
} __aal_cf_pattern_t;
typedef struct { __aal_cf_pattern_t data,mask; } __aal_cf_key_data_t;
#define AAL_L2_CF_MAX_RULE_ID 512
static unsigned int cf_stage[3], cf_rows[1024][3];
static void cf_write(unsigned int value,unsigned int address)
{
 assert(address>=L2FE_PONCLE_KEY_DATA2 && address<=L2FE_PONCLE_KEY_DATA0);
 cf_stage[(L2FE_PONCLE_KEY_DATA0-address)/4]=value;
}
static void cf_commit(unsigned int device,unsigned int index,unsigned int address)
{
 assert(!device && address==L2FE_PONCLE_KEY_ACCESS && index<1024);
 memcpy(cf_rows[index],cf_stage,sizeof(cf_stage));
}
#define CA_NE_REG_WRITE(value,address) cf_write(value,address)
#define WRITE_INDIRCT_REG(device,index,address) cf_commit(device,index,address)
'''

LIMIT_REFERENCE = r'''
/* Compare success-path writes from the unchanged SDK limit implementation.
 * Fault handling intentionally differs: the vendor restores CMD mode even
 * after timeout; production must retain RAW until both windows are idle. */
#undef CA_NE_REG_WRITE
#define L2_DEBUG(...) ((void)0)
struct limit_model {
 unsigned int control, data, rows[64], trace[16][2], count;
};
static struct limit_model limit_vendor, limit_native;
static unsigned int limit_read(struct limit_model *m,unsigned int address)
{
 if(address==L2FE_L2E_CTRL)return m->control;
 if(address==L2FE_L2E_PORT_MAC_CNT_LMT_DATA)return m->data;
 assert(address==L2FE_L2E_PORT_MAC_CNT_LMT_ACCESS || address==L2FE_L2E_FDB_ACCESS);
 return 0;
}
static void limit_write(struct limit_model *m,unsigned int address,unsigned int value)
{
 assert(m->count<16);m->trace[m->count][0]=address;m->trace[m->count++][1]=value;
 if(address==L2FE_L2E_CTRL)m->control=value;
 else if(address==L2FE_L2E_PORT_MAC_CNT_LMT_DATA)m->data=value;
 else {
  L2FE_L2E_PORT_MAC_CNT_LMT_ACCESS_t access={.wrd=value};
  assert(address==L2FE_L2E_PORT_MAC_CNT_LMT_ACCESS && access.bf.access);
  assert(!(m->control&RTL_L2_FDB_CMD_MODE));
  assert((access.bf.addr&~63U)==CA_AAL_L2E_LMT_ACCESS);
  if(access.bf.rbw)m->rows[access.bf.addr&63]=m->data;
  else m->data=m->rows[access.bf.addr&63];
 }
}
static unsigned int limit_native_read(void *context,unsigned int address)
{ return limit_read(context,address+0xf4300000U); }
static void limit_native_write(void *context,unsigned int address,unsigned int value)
{ limit_write(context,address+0xf4300000U,value); }
static int limit_native_request(void *context,unsigned int address,unsigned int value)
{ limit_native_write(context,address,value);return 0; }
#define CA_NE_REG_READ(address) limit_read(&limit_vendor,address)
#define FDB_REG_WRITE(address,value) limit_write(&limit_vendor,address,value)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
'''

PRIORITY_REFERENCE = r'''
#undef CA_NE_REG_READ
#define CA_ASSERT_RET(condition,error) do { if(!(condition))return error; } while(0)
#define ca_printf(...) ((void)0)
static unsigned int priority_reads, priority_current;
static void priority_request(unsigned int device,unsigned int index,unsigned int address)
{
 assert(!device && address==L2FE_PP_SPKTP_ACCESS && index<31);
 priority_reads++;priority_current=index;
}
static unsigned int priority_read(unsigned int address)
{ assert(address==L2FE_PP_SPKTP_DATA);return priority_current; }
#define READ_INDIRCT_REG(device,index,address) priority_request(device,index,address)
#define CA_NE_REG_READ(address) priority_read(address)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wtype-limits"
'''

TESTS = r'''
static uint32_t random_state=0x9617c10;
static uint32_t next_random(void)
{
 random_state^=random_state<<13;random_state^=random_state>>17;
 random_state^=random_state<<5;return random_state;
}
static void check_limit(void)
{
 assert(OFFSET(L2FE_L2E_PORT_MAC_CNT_LMT_ACCESS)==RTL_L2_FDB_LIMIT_ACCESS);
 assert(OFFSET(L2FE_L2E_PORT_MAC_CNT_LMT_DATA)==RTL_L2_FDB_LIMIT_DATA);
 assert(CA_AAL_L2E_LMT_ACCESS==RTL_L2_FDB_LIMIT_SELECT);
 L2FE_L2E_PORT_MAC_CNT_LMT_DATA_t field={.wrd=~0U};
 assert(field.bf.val==RTL_L2_FDB_LIMIT_MAX);
 for(unsigned int port=0;port<64;port++)for(unsigned int write=0;write<2;write++) {
  memset(&limit_vendor,0,sizeof(limit_vendor));
  limit_vendor.control=next_random()|RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE;
  for(unsigned int i=0;i<64;i++)limit_vendor.rows[i]=next_random();
  limit_native=limit_vendor;
  struct rtl_dq_io io={.context=&limit_native,.read=limit_native_read,
   .write=limit_native_write,.indirect=limit_native_request};
  unsigned int value=next_random(),expected=value,result=0;
  assert(!__aal_port_mac_lmt(0,port,write?__FDB_TBL_OPCODE_LMT_WR:__FDB_TBL_OPCODE_LMT_RD,
    &expected,&result));
  assert(result==CA_AAL_L3E_CNT_LMT_SUCCESS);
  int ret=write?rtl_l2_port_limit_write(&io,port,value):rtl_l2_port_limit_read(&io,port,&value);
  assert(!ret && value==expected && !memcmp(&limit_native,&limit_vendor,sizeof(limit_native)));
 }
}
static void check_classifier_gate(void)
{
 unsigned int native[7],reference[7]={0},lpb[3];
 cls_fib_mod_0_t ref={0};
 ref.dpid_vld=1;ref.dpid_pri=1;ref.permit=1;ref.mcgid=16;
 ref.keep_orig_pkt_vld=1;ref.keep_orig_pkt=1;ref.t2_ctrl_vld=1;
 ref.t2_ctrl=T2_CTRL_BYPASS;
 assert(sizeof(ref)<=sizeof(reference));memcpy(reference,&ref,sizeof(ref));
 rtl_fe_classify_cpu_original(native);assert(!memcmp(native,reference,sizeof(native)));
 /* No source rewrite, editing, policer, multicast, or vendor deep-Q bit. */
 assert(!ref.lspid_vld && !ref.deepq && !ref.mc && !ref.stage2_ctrl_vld);
 assert(L3_CLS_PROFILE_MAX==2 && L3_CLS_KEY_TBL_ENTRY_MAX==256);
 L3FE_CLS_KEY_TBL_ACCESS_t access={.wrd=0};access.bf.access=1;access.bf.addr=255;
 assert(access.wrd==(0x80000000U|255U));
 L3FE_CLS_KEY_TBL_DATA10_t key={.wrd=0};key.bf.cl_key_valid=15;
 assert(key.wrd==(15U<<27));
 assert(OFFSET(L3FE_CLS_KEY_TBL_ACCESS)==0x3380 && OFFSET(L3FE_CLS_KEY_TBL_DATA10)==0x3384);
 assert(OFFSET(L3FE_STG0_LPB_TBL_MID_1)==0x3418 && OFFSET(L3FE_STG0_LPB_TBL_MID_2)==0x3424);
 for(unsigned int source=0;source<64;source++) {
  rtl_fe_ingress_lpb(lpb,source,16);
  L3FE_STG0_LPB_TBL_MID_t mid={.wrd=lpb[1]};
  assert(mid.bf.t1_ctrl==0 && mid.bf.t5_ctrl==15);
  mid.bf.t1_ctrl=1;assert(mid.wrd==(lpb[1]|(1U<<10)));
 }
 /* Standard FIB reads its format from the adjacent second row, not only
  * the first mode0 payload. Caller must own and zero that row explicitly. */
 l3_cls_fib_tbl_entry_t second={0};second.fib_format_sel=7;
 unsigned int row[7];memcpy(row,&second,sizeof(row));
 assert(row[6]==(7U<<23));
}
static void check_special_priority(void)
{
 assert(OFFSET(L2FE_PP_RSV_GROUP_MAC_LOW)==RTL_L2_RESERVED_GROUP_MAC_LOW);
 assert(OFFSET(L2FE_PP_RSV_GROUP_MAC_HI)==RTL_L2_RESERVED_GROUP_MAC_HIGH);
 assert(OFFSET(L2FE_PP_RSV_GROUP_ENABLE_LOW)==RTL_L2_RESERVED_GROUP_MASK_LOW);
 assert(OFFSET(L2FE_PP_RSV_GROUP_ENABLE_HI)==RTL_L2_RESERVED_GROUP_MASK_HIGH);
 assert(L2FE_PP_RSV_GROUP_MAC_LOW_dft==RTL_L2_RESERVED_GROUP_MAC_LOW_DEFAULT);
 assert(L2FE_PP_RSV_GROUP_MAC_HI_dft==RTL_L2_RESERVED_GROUP_MAC_HIGH_DEFAULT);
 assert(L2FE_PP_RSV_GROUP_ENABLE_LOW_dft==RTL_L2_RESERVED_GROUP_MASK_LOW_DEFAULT);
 assert(L2FE_PP_RSV_GROUP_ENABLE_HI_dft==RTL_L2_RESERVED_GROUP_MASK_HIGH_DEFAULT);
 assert((int)RTL_L2_SPECIAL_IEEE_RESERVED_GROUP==AAL_L2_SPECPKT_TYPE_IEEE_RSVD_GRP);
 assert((int)RTL_L2_SPECIAL_NORMAL==AAL_L2_SPECPKT_TYPE_NORMAL);
 for(unsigned int i=0;i<32;i++) {
  aal_l2_specpkt_type_t value=AAL_L2_SPECPKT_TYPE_INVALID;
  priority_reads=0;assert(!aal_l2_specpkt_pri_get(0,i,&value));
  if(i<RTL_L2_SPECIAL_PRIORITIES)assert(priority_reads==1 && (unsigned int)value==i);
  else assert(!priority_reads && value==AAL_L2_SPECPKT_TYPE_INVALID);
 }
}
static void check_fdb(void)
{
 for(unsigned int i=0;i<16384;i++) {
  struct rtl_l2_fdb_entry e={0},back={0};
  unsigned int words[4],again[4];
  L2FE_L2E_FDB_DATA0_t d0={.wrd=0};L2FE_L2E_FDB_DATA1_t d1={.wrd=0};
  L2FE_L2E_FDB_DATA2_t d2={.wrd=0};L2FE_L2E_FDB_DATA3_t d3={.wrd=0};
  for(unsigned int j=0;j<6;j++)e.mac[j]=next_random();
  e.key_vid=next_random()&4095;e.key_sc=next_random()&1;
  e.key_dot1p=next_random()&7;e.learned_vid=next_random()&4095;e.learned_sc=next_random()&1;
  e.multicast=i&1;e.destination=next_random()&(e.multicast?1023:63);
  e.is_static=next_random()&1;e.sa_permit=next_random()&1;e.da_permit=next_random()&1;
  e.age=next_random();e.valid=e.multicast?1:(next_random()&1);
  e.temporary=e.multicast?0:(next_random()&1);
  e.in_refresh=e.multicast?0:(next_random()&1);
  e.in_station_move=e.multicast?0:(next_random()&1);e.untagged=next_random()&1;
  __aal_mac_2_fdb_data(&d3,&d2,&d1,e.mac);
  d3.bf.lrned_untag_vld=e.untagged;
  d1.bf.key_vid=e.key_vid;d1.bf.key_scind=e.key_sc;d1.bf.key_dot1p=e.key_dot1p;
  d1.bf.lrned_vid=e.learned_vid>>9;
  d0.bf.lrned_vid=e.learned_vid&511;d0.bf.lrned_scind=e.learned_sc;
  d0.bf.sa_permit=e.sa_permit;d0.bf.da_permit=e.da_permit;
  d0.bf.is_static=e.is_static;d0.bf.aging_sts=e.age;d0.bf.mc_flag=e.multicast;
  if(e.multicast)d0.bf.mcgid=e.destination;
  else {
   aal_fdb_data0_t u={.wrd=d0.wrd};u.bf.lpid=e.destination;u.bf.entry_valid=e.valid;
   u.bf.tmp_flag=e.temporary;u.bf.in_refresh_flag=e.in_refresh;u.bf.in_st_move_flag=e.in_station_move;
   d0.wrd=u.wrd;
  }
  assert(!rtl_l2_fdb_encode(words,&e));
  assert(words[0]==d0.wrd && words[1]==d1.wrd && words[2]==d2.wrd && words[3]==d3.wrd);
  rtl_l2_fdb_decode(words,&back);
  assert(!memcmp(e.mac,back.mac,6) && e.key_vid==back.key_vid && e.key_sc==back.key_sc);
  assert(e.key_dot1p==back.key_dot1p && e.learned_vid==back.learned_vid && e.learned_sc==back.learned_sc);
  assert(e.destination==back.destination && e.valid==back.valid && e.multicast==back.multicast);
  assert(e.is_static==back.is_static && e.age==back.age && e.temporary==back.temporary);
  assert(e.sa_permit==back.sa_permit && e.da_permit==back.da_permit && e.untagged==back.untagged);
  assert(e.in_refresh==back.in_refresh && e.in_station_move==back.in_station_move);
  assert(!rtl_l2_fdb_encode(again,&back) && !memcmp(words,again,sizeof(words)));
 }
 for(unsigned int bit=0;bit<48;bit++) {
  struct rtl_l2_fdb_entry e={.key_vid=4095,.key_sc=1,.valid=1,.is_static=1,.destination=16};
  unsigned int words[4];uint64_t mac=UINT64_C(1)<<bit;
  for(unsigned int j=0;j<6;j++)e.mac[j]=mac>>(8*(5-j));
  assert(!rtl_l2_fdb_encode(words,&e));
  L2FE_L2E_FDB_DATA1_t d1={.wrd=words[1]};
  L2FE_L2E_FDB_DATA2_t d2={.wrd=words[2]};
  L2FE_L2E_FDB_DATA3_t d3={.wrd=words[3]};
  assert((((uint64_t)d3.bf.mac_addr<<45)|((uint64_t)d2.bf.mac_addr<<13)|d1.bf.mac_addr)==mac);
  assert(d1.bf.key_vid==4095 && d1.bf.key_scind==1);
 }
}
static void check_cf(void)
{
 for(unsigned int source=0;source<64;source++)for(unsigned int type=0;type<5;type++) {
  __aal_cf_key_data_t sdk={0};unsigned int x[3],y[3];
  sdk.mask.key_data0.bf.lspid=63;sdk.data.key_data0.bf.lspid=source;
  sdk.mask.key_data0.bf.pkt_type=7;sdk.data.key_data0.bf.pkt_type=type;
  sdk.mask.key_data2.bf.valid=1;sdk.data.key_data2.bf.valid=1;
  assert(!__aal_l2_cf_key_write(source,&sdk));
  assert(!rtl_l2_cf_pkt_type_key(x,y,source,type));
  assert(!memcmp(x,cf_rows[source],sizeof(x)) && !memcmp(y,cf_rows[source+512],sizeof(y)));
 }
 for(unsigned int source=0;source<64;source++)for(unsigned int stag=0;stag<2;stag++) {
  __aal_cf_key_data_t sdk={0};unsigned int x[3],y[3],fib[3];
  sdk.mask.key_data0.bf.lspid=63;sdk.data.key_data0.bf.lspid=source;
  if(stag){sdk.mask.key_data0.bf.stag_pkt=1;sdk.data.key_data0.bf.stag_pkt=1;}
  else {sdk.mask.key_data0.bf.ctag_pkt=1;sdk.data.key_data0.bf.ctag_pkt=1;}
  sdk.mask.key_data2.bf.valid=1;sdk.data.key_data2.bf.valid=1;
  assert(!__aal_l2_cf_key_write(source,&sdk));
  assert(!rtl_l2_cf_tag_key(x,y,source,stag));
  assert(!memcmp(x,cf_rows[source],sizeof(x)) && !memcmp(y,cf_rows[source+512],sizeof(y)));
  for(unsigned int destination=0;destination<64;destination++) {
   L2FE_PONCLE_FIB_DATA1_t ref={.wrd=0};
   ref.bf.forward_act=AAL_L2_CF_ACTION_FWD_ACT_LDPID;ref.bf.cf_fwd_id=destination;
   assert(!rtl_l2_cf_destination(fib,destination));
   assert(!fib[0] && fib[1]==ref.wrd && !fib[2]);
  }
 }
}
static void check_constants(void)
{
 assert(FE_SW_TPID_STANDARD == ((1U<<AAL_VLAN_TPID_INDEX_8100) |
   (1U<<AAL_VLAN_TPID_INDEX_9100) | (1U<<AAL_VLAN_TPID_INDEX_88A8)));
 assert(FE_SW_TPID_USER == (1U<<AAL_VLAN_TPID_INDEX_USER_DEFINE));
 for(unsigned int bits=0;bits<16;bits++) {
  ca_uint32_t list[4]={0},count=0;
  __l2_vlan_tpid_bmp2list(bits,list,&count);
  unsigned int expected=0;
  for(unsigned int i=1;i<4;i++)if(bits&(1U<<i)) {
   assert(expected<count);
   assert(list[expected++]==(i==AAL_VLAN_TPID_INDEX_88A8?0x88a8U:
      i==AAL_VLAN_TPID_INDEX_9100?0x9100U:0x8100U));
  }
  assert(count==expected);
 }
 ca_uint32_t list[4]={0},count=0;
 __l2_vlan_tpid_bmp2list(FE_SW_TPID_ALL,list,&count);
 assert(count==3 && list[0]==0x88a8 && list[1]==0x9100 && list[2]==0x8100);
 assert((int)RTL_L2_FLOOD_BROADCAST==AAL_PLE_NONKWN_TYPE_BC);
 assert((int)RTL_L2_FLOOD_UNKNOWN_UNICAST==AAL_PLE_NONKWN_TYPE_UUC);
 assert((int)RTL_L2_FLOOD_UNKNOWN_L2_MULTICAST==AAL_PLE_NONKWN_TYPE_UL2MC);
 assert((int)RTL_L2_FLOOD_UNKNOWN_L3_MULTICAST==AAL_PLE_NONKWN_TYPE_UL3MC);
 assert((int)RTL_L2_CF_UNICAST==AAL_L2_CF_PATTEN_PKT_TYPE_UC);
 assert((int)RTL_L2_CF_BROADCAST==AAL_L2_CF_PATTEN_PKT_TYPE_BC);
 assert((int)RTL_L2_CF_MULTICAST==AAL_L2_CF_PATTEN_PKT_TYPE_MC);
 assert((int)RTL_L2_CF_UNKNOWN_UNICAST==AAL_L2_CF_PATTEN_PKT_TYPE_UUC);
 assert((int)RTL_L2_CF_UNKNOWN_MULTICAST==AAL_L2_CF_PATTEN_PKT_TYPE_UMC);
 assert(OFFSET(L2FE_PP_TPID_CMP_S)==RTL_L2_PP_TPID_S);
 assert(OFFSET(L2FE_PP_TPID_CMP_C)==RTL_L2_PP_TPID_C);
 assert(OFFSET(L2FE_PP_TPID_CMP_O)==RTL_L2_PP_TPID_OTHER);
 assert(OFFSET(L2FE_PP_TPID_CMP_USER)==RTL_L2_PP_TPID_USER);
 assert(RTL_L2_DSCP_KEEP_RECEIVED==AAL_DSCP_MODE_RX_DSCP);
 assert(RTL_L2_PRIORITY_KEEP_RECEIVED==AAL_DOT1P_MODE_RX_DOT1P_OR_PORT_DEF);
 assert(OFFSET(L2FE_PLC_VLAN_MODE_CTRL)==RTL_L2_VLAN_MODE_CONTROL);
 L2FE_PLC_VLAN_MODE_CTRL_t vlan={.wrd=0};vlan.bf.l2e_glb_vlan_mode=AAL_L2_VLAN_MODE_SVL;
 assert(vlan.wrd==RTL_L2_VLAN_MODE_SVL);
 assert(OFFSET(L2FE_PLC_HASH_CTRL)==RTL_L2_FDB_HASH_CONTROL);
 L2FE_PLC_HASH_CTRL_t hash={.wrd=0};hash.bf.use_dot1p_l2e=1;
 assert(hash.wrd==RTL_L2_FDB_HASH_USE_PRIORITY);
 assert(RTL_L2_FDB_ENTRIES==AAL_FDB_MAX_NUM && RTL_L2_FDB_MAIN_ENTRIES==AAL_FDB_TABLE_SIZE);
 assert(RTL_L2_FDB_OVERFLOW_ENTRIES==AAL_FDB_OVERFLOW_TABLE_SIZE);
 assert((int)RTL_L2_FDB_SCAN==__FDB_TBL_OPCODE_SCAN && (int)RTL_L2_FDB_READ==__FDB_TBL_OPCODE_READ);
 assert((int)RTL_L2_FDB_APPEND==__FDB_TBL_OPCODE_APPEND && (int)RTL_L2_FDB_DELETE==__FDB_TBL_OPCODE_DELETE);
 assert((int)RTL_L2_STP_DROP==AAL_STP_STATE_DROP);
 assert((int)RTL_L2_STP_LEARN_NO_FORWARD==AAL_STP_STATE_LEARN_NO_FWD);
 assert((int)RTL_L2_STP_FORWARD_NO_LEARN==AAL_STP_STATE_FWD_NO_LEARN);
 assert((int)RTL_L2_STP_FORWARD_AND_LEARN==AAL_STP_STATE_FWD_AND_LEARN);
 assert(RTL_L2_MC_COS_REPLACE==MCFIB_COS_CMD_EN && RTL_L2_MC_COS_KEEP==MCFIB_COS_CMD_DIS);
 assert(RTL_L2_MC_FIB_ENTRIES==ARB_FIB_TBL_ENTRY_MAX && RTL_L2_MC_VECTOR_ENTRIES==MCE_INDX_TBL_ENTRY_MAX);
 L2FE_L2E_CTRL_t ctl={.wrd=RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_LEARN_HW|RTL_L2_FDB_COLLISION_OVERWRITE};
 assert(ctl.bf.cpu_opt_mode==1 && ctl.bf.lrn_dis==1 && ctl.bf.lrn_mode==1 && ctl.bf.hash_collision_overwrite==1);
 assert(OFFSET(L2FE_L2E_CTRL)==RTL_L2_FDB_CONTROL && OFFSET(L2FE_L2E_FDB_ACCESS)==RTL_L2_FDB_ACCESS);
 assert(OFFSET(L2FE_L2E_FDB_CMD_RETURN)==RTL_L2_FDB_RETURN && OFFSET(L2FE_L2E_FDB_DATA0)==RTL_L2_FDB_DATA0);
 assert(OFFSET(L2FE_L2E_FDB_CPU_CMD_WORD0)==RTL_L2_FDB_FILTER_WORD0);
 assert(L2FE_L2E_FDB_CPU_CMD_WORD1==L2FE_L2E_FDB_CPU_CMD_WORD0-4);
 assert(L2FE_L2E_FDB_CPU_CMD_WORD2==L2FE_L2E_FDB_CPU_CMD_WORD0-8);
 assert(L2FE_L2E_FDB_CPU_CMD_WORD3==L2FE_L2E_FDB_CPU_CMD_WORD0-12);
 assert(L2FE_L2E_FDB_CPU_CMD_WORD4==L2FE_L2E_FDB_CPU_CMD_WORD0-16);
 for(unsigned int i=0;i<1024;i++) {
  unsigned int words[5],expected[5];
  for(unsigned int j=0;j<5;j++)words[j]=expected[j]=next_random();
  aal_fdb_cpu_cmd_word0_t lo={.wrd=words[0]};lo.bf.lpid_low=0;
  aal_fdb_cpu_cmd_word1_t hi={.wrd=words[1]};hi.bf.lpid_high=63;
  aal_fdb_cpu_cmd_word4_msk_t mask={.wrd=~0U};mask.bf.lpid=0;
  L2FE_L2E_FDB_CPU_CMD_WORD4_t field={.wrd=words[4]};field.bf.word=mask.wrd;
  expected[0]=lo.wrd;expected[1]=hi.wrd;expected[4]=field.wrd;
  rtl_l2_fdb_scan_filter(words);assert(!memcmp(words,expected,sizeof(words)));
  assert(mask.bf.invalid_entry==1 && mask.bf.mc_flag==1 && mask.bf.static_flag==1);
 }
 for(unsigned int bit=0;bit<64;bit++) {
  uint64_t bitmap=UINT64_C(1)<<bit;unsigned int words[2];
  rtl_l2_bitmap_encode(words,bitmap);assert(rtl_l2_bitmap_decode(words)==bitmap);
  NI_HV_MCE_INDX_LKUP_DATA0_t low={.wrd=words[0]};NI_HV_MCE_INDX_LKUP_DATA1_t high={.wrd=words[1]};
  assert((((uint64_t)high.bf.mc_vec<<32)|low.bf.mc_vec)==bitmap);
 }
}
int main(void)
{
 check_fields();check_tables();check_fdb();check_cf();check_constants();check_limit();check_classifier_gate();
 check_special_priority();
 printf("Pinned RTL77C L2 SDK oracle: %u fields, %u windows, 16384 FDB vectors, "
   "48 MAC bits, 448 PONCLE keys, 128 SDK MAC-limit traces, CLS CPU-original gate, SPKTP bounds, "
   "fixed/user TPID bitmap decoder, SCAN filters and 64-bit MC/port bitmap contracts PASS (model only)\n",
   RTL_L2_FIELD_COUNT,RTL_L2_TBL_COUNT);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--registers", required=True, type=Path)
    args = parser.parse_args()
    base = args.sdk / "ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c"
    sdk = {name: checked(base / name, digest) for name, digest in SDK_FILES.items()}
    registers = checked(args.registers, REG_HASH)
    source = compile_source(registers, sdk)
    with tempfile.TemporaryDirectory(prefix="l2-sdk-contract-") as temporary:
        directory = Path(temporary)
        c_file, binary = directory / "test.c", directory / "test"
        c_file.write_text(source)
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I", str(DRIVER),
                        str(c_file), "-o", str(binary)], check=True)
        environment = dict(os.environ)
        environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
        subprocess.run([str(binary)], check=True, env=environment)
    print(f"Reference: ca-network-drivers@{SDK_PIN}; GPL-for-GP3000@{REG_PIN}; all SHA256 checked")


if __name__ == "__main__":
    main()
