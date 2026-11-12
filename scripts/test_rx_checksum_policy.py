#!/usr/bin/env python3
"""Exercise the production IPv4/PPPoE checksum acceptance parser on host bytes.

EPP bit 5 semantics under PPPoE still require on-device good/bad captures;
the optional PPPoE fast path remains disabled in firmware by default.
"""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
header = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-rx-checksum.h'
test = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-rx-checksum.h"

static void make_udp(unsigned char *p, bool pppoe) {
 unsigned offset=pppoe?22:14;
 memset(p,0,64);
 p[12]=pppoe?0x88:0x08;p[13]=pppoe?0x64:0x00;
 if(pppoe){p[14]=0x11;p[18]=0;p[19]=30;p[20]=0;p[21]=0x21;}
 p[offset]=0x45;p[offset+2]=0;p[offset+3]=28;
 p[offset+9]=17;p[offset+24]=0;p[offset+25]=8;
 p[offset+26]=0x12;p[offset+27]=0x34;
}
int main(void){
 unsigned char frame[64];
 make_udp(frame,false);
 assert(rtl_rx_checksum_valid(0,frame,42));
 assert(!rtl_rx_checksum_valid(1U<<5,frame,42));
 assert(!rtl_rx_checksum_valid(0,frame,41));
 frame[14]=0x46;assert(!rtl_rx_checksum_valid(0,frame,42));
 make_udp(frame,true);
 assert(rtl_rx_checksum_valid(0,frame,50));
 assert(!rtl_rx_checksum_valid(1U<<5,frame,50));
 assert(!rtl_rx_checksum_valid(0,frame,49));
 frame[19]=31;assert(!rtl_rx_checksum_valid(0,frame,50));
 frame[19]=30;frame[21]=0x57;assert(!rtl_rx_checksum_valid(0,frame,50));
 frame[21]=0x21;frame[15]=1;assert(!rtl_rx_checksum_valid(0,frame,50));
 frame[15]=0;frame[22+25]=9;assert(!rtl_rx_checksum_valid(0,frame,50));
 puts("Production RX checksum parser: IPv4/PPPoE UDP, corrupted status, malformed lengths and protocol rejection passed");
}
'''
with tempfile.TemporaryDirectory(prefix='rx-checksum-', dir=root / 'artifacts') as temporary:
    src = Path(temporary) / 'test.c'
    exe = Path(temporary) / 'test'
    src.write_text(test)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(header.parent),
                    str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
