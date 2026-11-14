#!/usr/bin/env python3
"""Execute pinned RTL77C frame-size APIs and inspect their independent fields.

The SDK owns UNI RX MRU independently of the packet-storage limit. This
oracle does not claim tag-aware GE limits or an oversize-only CPU trap.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
PINS = {
    'sdk_ni': 'b9a44c40b07e484ef017653afdb60e19d20163a3c12e64d435c0880319cf14e7',
    'sdk_ni_header': 'a27f44301c5062e81779e51876566ce4054a836b1f8fa27f5f4807827adeefaa',
    'sdk_eth': '73a0c54d6bfab0ff573474b28d03e90d875d46a9f56d83826bff8019839ca70f',
    'registers': 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0',
    'fc_acl': '18e88659762c1844f72df211e3d8783f8ec490fc97e8367fbef532add31626e8',
}


def function(text, name):
    found = re.search(r'(?m)^[\w *]+\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', text)
    assert found, name
    end = text.index('{', found.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[found.start():end] + '\n'


def typedef(text, name):
    end = re.search(r'}\s*' + re.escape(name) + r';', text).end()
    return text[text.rfind('typedef ', 0, end):end] + '\n'


def constant(text, name):
    return re.search(r'^#define\s+' + re.escape(name) + r'\s+[^\n]+', text, re.M)[0] + '\n'


def register(text, name):
    start = re.search(r'^#define ' + re.escape(name) + r'\s+0x', text, re.M).start()
    end = text.index('#endif /* !__ASSEMBLER__ */', start)
    return text[start:end] + '#endif /* !__ASSEMBLER__ */\n'


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-l2-format.h"
#include "rtl9617c-frame.h"
typedef unsigned int ca_uint32_t,ca_device_id_t,ca_port_id_t;
typedef uint16_t ca_uint16_t;
typedef unsigned char ca_boolean_t;
typedef int ca_status_t;
#define CA_IN
#define CA_OUT
#define CA_E_OK 0
#define CA_E_PARAM (-EINVAL)
#define AAL_ASSERT_RET(ok,err) do {if(!(ok))return err;}while(0)
#define __NI_ASSERT(ok) AAL_ASSERT_RET(ok,CA_E_PARAM)
#define __NI_PORT_CHK(dev,port) do{assert(!(dev));AAL_ASSERT_RET((port)<12,CA_E_PARAM);}while(0)
#define __XGE_PORT_CHK(port) AAL_ASSERT_RET((port)<__NI_XGE_NUM,CA_E_PARAM)
#define __NI_PORT_REG_STRIDE APB0_NI_HV_PT_STRIDE
/* Port encoding/registration is the public API boundary fixture. The real
 * SDK GE and XGE branches and all register setters below are unchanged. */
#define CA_DEV_ID_CHECK(dev) assert(!(dev))
#define __ETH_INIT_CHK(dev) assert(!(dev))
#define __ETH_PORT_CHK(port) assert((port)<8)
#define __ETH_PORT_UNLOCK(dev) assert(!(dev))
#define PORT_ID(port) (port)
#define CA_PORT_IS_GE(port) ((port)<5)
#define CA_PORT_IS_XGE(port) ((port)==6 || (port)==7)
static uint32_t registers[0x10000/4];
static unsigned writes,reads,delays,last_address;
static uint32_t read_reg(unsigned device,unsigned address){
 assert(!device && address>=0xf4300000U && address<0xf4310000U && !(address&3));
 reads++;return registers[(address-0xf4300000U)/4];
}
static void write_reg(unsigned device,unsigned address,uint32_t value){
 assert(!device && address>=0xf4300000U && address<0xf4310000U && !(address&3));
 writes++;last_address=address;registers[(address-0xf4300000U)/4]=value;
}
static void ca_mdelay(unsigned msec){assert(msec==1);delays++;}
#define CA_DEV_NI_REG_READ(dev,reg) read_reg(dev,reg)
#define CA_DEV_NI_REG_WRITE2(dev,reg,value) write_reg(dev,reg,value)
'''


CASES = r'''
static void reset(void){
 for(unsigned i=0;i<sizeof(registers)/sizeof(registers[0]);i++)registers[i]=0xa5961700U^(i*0x01235U);
 registers[0xa034/4]=0x004023f1;registers[0xa038/4]=0xb4002454;
 writes=reads=delays=last_address=0;
}
static void check_ge(void){
 assert(FABRIC_FRAME_BUDGET==1500+14+8+4); /* coarse wire MRU with QinQ room */
 assert(OFFSET_NI_FRAME==NI_HV_GLB_PKT_LEN_CFG-0xf4300000U);
 assert(OFFSET_NI_STORAGE==NI_HV_GLB_PKT_STOR_LEN_CFG-0xf4300000U);
 NI_HV_PT_RX_CNTRL_CFG_t flag={.wrd=0};flag.bf.ovr_drop_dis=1;
 assert(flag.wrd==FABRIC_OVERSIZE_BIT);
 for(unsigned port=0;port<5;port++){
  reset();unsigned before=registers[0xa034/4],storage=registers[0xa038/4];
  assert(!ca_eth_port_max_frame_size_set(0,port,FABRIC_FRAME_BUDGET));
  assert(writes==1 && last_address==NI_HV_GLB_PKT_LEN_CFG && delays==1);
  NI_HV_GLB_PKT_LEN_CFG_t cap={.wrd=before};cap.bf.max_pkt_size=FABRIC_FRAME_BUDGET;
  assert(registers[0xa034/4]==cap.wrd && registers[0xa038/4]==storage);
  aal_ni_pkt_len_config_t got={0};assert(!aal_ni_pkt_len_get(0,&got));
  assert(got.min_pkt_size==64 && got.max_pkt_size==FABRIC_FRAME_BUDGET);
  assert(got.max_store_pkt_len==(storage&0x3fff));
  unsigned address=NI_HV_PT_RX_CNTRL_CFG+port*APB0_NI_HV_PT_STRIDE;
  unsigned old=registers[(address-0xf4300000U)/4]|FABRIC_OVERSIZE_BIT;
  old=port&1?old|(1U<<28):old&~(1U<<28);
  registers[(address-0xf4300000U)/4]=old;
  aal_ni_port_rx_ctrl_mask_t mask={.u32=0};aal_ni_port_rx_ctrl_t cfg={0};
  mask.s.ovr_drop_dis=1;assert(!aal_ni_port_rx_ctrl_set(0,port,mask,&cfg));
  assert(last_address==address && registers[(address-0xf4300000U)/4]==(old&~FABRIC_OVERSIZE_BIT));
  assert(!aal_ni_port_rx_ctrl_get(0,port,&cfg) && !cfg.ovr_drop_dis);
  NI_HV_PT_RX_CNTRL_CFG_t expected={.wrd=old};
  assert(cfg.rxctrl_byp_en==expected.bf.rxctrl_byp_en); /* independent bypass, not error-only */
 }
 const unsigned sizes[]={63,12001};
 for(unsigned i=0;i<2;i++){
  reset();unsigned before=registers[0xa034/4],storage=registers[0xa038/4];
  assert(ca_eth_port_max_frame_size_set(0,0,sizes[i])==CA_E_PARAM);
  assert(!writes && !delays && registers[0xa034/4]==before && registers[0xa038/4]==storage);
 }
}
static void check_xge(void){
 reset();unsigned uni=registers[0xa034/4],storage=registers[0xa038/4];
 assert(!ca_eth_port_max_frame_size_set(0,6,FABRIC_FRAME_BUDGET));
 assert(writes==1 && last_address==NI_HV_XGE_MAC_MAXLEN && !delays);
 assert(registers[0xa034/4]==uni && registers[0xa038/4]==storage);
 aal_ni_xge_mac_frame_len_config_mask_t mask={.u32=0};
 aal_ni_xge_mac_frame_len_config_t cfg={0};
 mask.s.maxlen_mode=1;cfg.maxlen_mode=1;
 unsigned old=registers[(NI_HV_XGE_MAC_CFG_RX-0xf4300000U)/4];
 assert(!aal_ni_xge_mac_frame_len_set(0,0,mask,&cfg));
 NI_HV_XGE_MAC_CFG_RX_t expected={.wrd=old};expected.bf.maxlen_mode=1;
 assert(registers[(NI_HV_XGE_MAC_CFG_RX-0xf4300000U)/4]==expected.wrd);
 writes=0;assert(aal_ni_xge_mac_frame_len_set(0,1,mask,&cfg)==CA_E_PARAM);
 assert(!writes); /* actual-ETH index explicitly rejected by this SDK API */
}
static void check_cpu_tag_traps(void){
 for(unsigned port=0;port<5;port++)for(unsigned stag=0;stag<2;stag++){
  unsigned x[3],y[3],fib[3];
  assert(!rtl_l2_cf_tag_key(x,y,port,stag));
  L2FE_PONCLE_KEY_DATA0_t select={.wrd=x[0]^y[0]},value={.wrd=~x[0]&y[0]};
  assert(select.bf.lspid==63 && value.bf.lspid==port);
  assert(stag?(select.bf.stag_pkt&&value.bf.stag_pkt):(select.bf.ctag_pkt&&value.bf.ctag_pkt));
  assert(!rtl_l2_cf_destination(fib,16));
  L2FE_PONCLE_FIB_DATA1_t action={.wrd=fib[1]};
  assert(action.bf.forward_act==3 && action.bf.cf_fwd_id==16 && !fib[0] && !fib[2]);
 }
}
int main(void){check_ge();check_xge();check_cpu_tag_traps();puts("PASS: pinned SDK GE MRU/storage, oversize bit, separate XGE AUTO and tag-CPU encoding");}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in PINS:
        parser.add_argument('--'+key.replace('_','-'), type=Path, required=True)
    args = parser.parse_args()
    sources = {}
    for key,digest in PINS.items():
        raw = getattr(args,key).read_bytes()
        assert hashlib.sha256(raw).hexdigest()==digest, ('unpinned source',key)
        sources[key]=raw.decode()
    ni,header,regs = (sources[k] for k in ('sdk_ni','sdk_ni_header','registers'))
    assert 'Maximum allowed Rx Packet size for UNI ports' in header
    assert 'Maximum  packet length allowed in Golden Gate(include Tx/Rx and processing)' in header
    assert '1 VLAN tag: MAXLEN+4' in header and '2 VLAN tags: MAXLEN+8' in header
    acl=sources['fc_acl'];start=acl.index('case RTK_FC_ACLANDCF_RESERVED_MC_JUMBO_DROP:')
    # The first occurrence is the actual predicate construction, not its label
    # initializer or the later resource-count switch.
    case=acl[start:re.search(r'\n\s*default\s*:',acl[start:]).start()+start]
    assert case.count('cam_pkt_len.pkt_len_low = 12000')==2
    assert case.count('cam_pkt_len.pkt_len_hi = 16383')==2
    assert 'AAL_TABLE_L3_CAM_PKT_LEN' in case and 'pktlen_rng_match_vec' in case
    assert 'SPECPKT_TYPE_JUMBO' not in case and 'special_pkt_code' not in case
    names=('NI_HV_GLB_PKT_LEN_CFG','NI_HV_GLB_PKT_STOR_LEN_CFG','NI_HV_PT_RX_CNTRL_CFG',
           'NI_HV_XGE_MAC_CFG_RX','NI_HV_XGE_MAC_MINLEN','NI_HV_XGE_MAC_MAXLEN',
           'L2FE_PONCLE_KEY_DATA0','L2FE_PONCLE_FIB_DATA1')
    unit=COMMON+'\n'.join(register(regs,name) for name in names)
    unit+=constant(regs,'APB0_NI_HV_PT_STRIDE')
    for name in ('AAL_NI_PKT_LEN_MIN','AAL_NI_PKT_LEN_MAX','AAL_NI_XGE_MAC_MINLEN_MAX',
                 'AAL_NI_XGE_MAC_MAXLEN_MAX','AAL_NI_PORT_XGE1','AAL_NI_XE_START'):
        unit+=constant(header,name)
    for name in ('__NI_XGE_NUM','__NI_XGE_ACT_ETH_IDX','__NI_XGE_REG_STRIDE'):
        unit+=constant(ni,name)
    for name in ('aal_ni_pkt_len_config_mask_t','aal_ni_pkt_len_config_t',
                 'aal_ni_port_rx_ctrl_mask_t','aal_ni_port_rx_ctrl_t',
                 'aal_ni_xge_mac_frame_len_config_mask_t','aal_ni_xge_mac_frame_len_config_t'):
        unit+=typedef(header,name)
    for name in ('aal_ni_pkt_len_set','aal_ni_pkt_len_get','aal_ni_port_rx_ctrl_set',
                 'aal_ni_port_rx_ctrl_get','aal_ni_xge_mac_frame_len_set'):
        unit+=function(ni,name)
    unit+=function(sources['sdk_eth'],'ca_eth_port_max_frame_size_set')
    fabric=(DRIVER/'rtl9617c-fabric.h').read_text()
    for native,oracle in (('RTL_FABRIC_NATIVE_MAX_FRAME','FABRIC_FRAME_BUDGET'),
                          ('RTL_FABRIC_FRAME_LENGTH','OFFSET_NI_FRAME'),
                          ('RTL_FABRIC_STORAGE_LENGTH','OFFSET_NI_STORAGE'),
                          ('RTL_FABRIC_RX_OVERSIZE_ALLOW','FABRIC_OVERSIZE_BIT')):
        unit+=constant(fabric,native).replace(native,oracle)
    unit+=CASES
    mutants={
        'storage_mistaken_for_uni':unit.replace('ge_msk.s.max_pkt_size = 1;', 'ge_msk.s.max_store_pkt_len = 1;',1),
        'wrong_ge_oversize_bit':unit.replace('reg_cfg.bf.ovr_drop_dis = config->ovr_drop_dis;', 'reg_cfg.bf.crc_drop_dis = config->ovr_drop_dis;',1),
        'single_tag_only_budget':unit.replace('#define FABRIC_FRAME_BUDGET RTL_NI_FRAME_WIRE_BYTES','#define FABRIC_FRAME_BUDGET 1522U',1),
    }
    assert all(value!=unit for value in mutants.values())
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    with tempfile.TemporaryDirectory(prefix='fabric-sdk-framing-') as temporary:
        work=Path(temporary);binary=work/'test';source=work/'test.c'
        for name,text in [('production',unit),*mutants.items()]:
            source.write_text(text)
            subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                            '-Wno-unused-function','-fsanitize=address,undefined','-fno-omit-frame-pointer',
                            '-I',str(DRIVER),str(source),'-o',str(binary)],check=True)
            result=subprocess.run([str(binary)],text=True,capture_output=True,
                                  env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0','UBSAN_OPTIONS':'halt_on_error=1'})
            if name=='production':
                assert not result.returncode,result.stderr
                print(result.stdout.strip())
            else:
                assert result.returncode and 'Assertion' in result.stderr,(name,result.stderr)
                print('PASS: framing oracle rejected '+name)
    evidence={'sources_sha256':PINS,'coarse_uni_wire_mru':1526,'storage_limit_modified':False,
              'ge_tag_aware_check_proven':False,'spb_jumbo_detector_proven':False,
              'oversize_only_cpu_trap_proven':False,'mc_jumbo_protection':'L3 CAM range 12000..16383',
              'hardware_forwarding_proven':False,'negative_controls':list(mutants)}
    (ROOT/'artifacts').mkdir(exist_ok=True)
    (ROOT/'artifacts/fabric-sdk-framing.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print('PASS: pinned MC jumbo protection is L3 length classification; no SPB detector claim')


if __name__=='__main__':
    main()
