#!/usr/bin/env python3
"""Validate compiled production DTBs using a dependency-free FDT decoder.

This checks the binary DTB, including inherited status. It proves neither boot
success nor GPIO/PON hardware behavior. Each real input also gets an in-memory
negative control restoring the unverified cold-handoff property.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

NI_PATH = '/soc/ethernet@4f4300000'
NI_COMPATIBLE = 'realtek,rtl9617c-xram-eth'
COLD_FLAG = 'realtek,pon-cold-handoff'


class DtbError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise DtbError(message)


def cstring(blob, offset, end):
    require(0 <= offset < end <= len(blob), 'string outside declared block')
    finish = blob.find(b'\0', offset, end)
    require(finish >= 0, 'unterminated FDT string')
    return blob[offset:finish].decode('ascii'), finish + 1


def decode(blob):
    require(40 <= len(blob) <= 4 * 1024 * 1024, 'DTB size outside supported bounds')
    header = struct.unpack_from('>10I', blob)
    magic,total,off_struct,off_strings,off_reserve,version,last_version,boot_cpu,size_strings,size_struct = header
    require(magic == 0xd00dfeed and total == len(blob), 'invalid FDT header/total size')
    require(version == 17 and last_version <= 17, 'expected version-17 FDT')
    require(off_struct % 4 == 0 and off_reserve % 8 == 0, 'unaligned FDT block')
    ranges = [(off_struct,off_struct+size_struct), (off_strings,off_strings+size_strings)]
    for start,end in ranges:
        require(40 <= start <= end <= total, 'FDT block outside blob')
    require(ranges[0][1] <= ranges[1][0] or ranges[1][1] <= ranges[0][0], 'overlapping FDT blocks')
    reserve_end = off_reserve
    while True:
        require(40 <= reserve_end and reserve_end+16 <= total, 'truncated reserve map')
        address,size = struct.unpack_from('>QQ', blob, reserve_end)
        reserve_end += 16
        if address == size == 0:
            break
    require(all(reserve_end <= start or end <= off_reserve for start,end in ranges), 'reserve map overlaps block')
    nodes,close_offsets = {},{}
    stack=[]
    cursor,end = off_struct,off_struct+size_struct
    finished=False
    while cursor < end:
        require(cursor+4 <= end, 'truncated structure token')
        token=struct.unpack_from('>I',blob,cursor)[0]
        token_start=cursor
        cursor+=4
        if token==1:
            name,cursor=cstring(blob,cursor,end)
            cursor=(cursor+3)&~3
            require('/' not in name and (stack or name==''), 'invalid node name/root')
            path='/' if not stack else stack[-1].rstrip('/')+'/'+name
            require(path not in nodes, 'duplicate FDT node')
            nodes[path]={}
            stack.append(path)
        elif token==2:
            require(stack, 'unbalanced END_NODE')
            close_offsets[stack.pop()]=token_start-off_struct
        elif token==3:
            require(stack and cursor+8 <= end, 'property outside node or truncated')
            length,name_offset=struct.unpack_from('>II',blob,cursor)
            cursor+=8
            require(name_offset < size_strings, 'property name outside strings')
            name,_=cstring(blob,off_strings+name_offset,off_strings+size_strings)
            require(cursor+length <= end and name not in nodes[stack[-1]], 'truncated/duplicate property')
            nodes[stack[-1]][name]=blob[cursor:cursor+length]
            cursor=(cursor+length+3)&~3
        elif token==4:
            continue
        elif token==9:
            require(not stack and '/' in nodes, 'END before root closed')
            require(not any(blob[cursor:end]), 'data after END token')
            finished=True
            break
        else:
            raise DtbError(f'unknown FDT token {token}')
    require(finished, 'missing FDT END token')
    return {'nodes':nodes, 'close_offsets':close_offsets, 'header':header,
            'reserve':blob[off_reserve:reserve_end],
            'structure':blob[off_struct:off_struct+size_struct],
            'strings':blob[off_strings:off_strings+size_strings]}


def string_list(value):
    require(value.endswith(b'\0'), 'non-terminated string property')
    return value[:-1].decode('ascii').split('\0')


def validate(blob):
    tree=decode(blob)
    nodes=tree['nodes']
    matching=[path for path,props in nodes.items()
              if 'compatible' in props and NI_COMPATIBLE in string_list(props['compatible'])]
    require(matching==[NI_PATH], f'expected exactly one native NI node at {NI_PATH}; found {matching}')
    statuses={}
    parts=NI_PATH.strip('/').split('/')
    for index in range(len(parts)+1):
        path='/'+'/'.join(parts[:index])
        value=nodes[path].get('status')
        statuses[path]='absent (enabled)' if value is None else string_list(value)[0]
        require(value is None or string_list(value) in (['okay'],['ok']), f'NI/ancestor disabled: {path}')
    # Presence, including an empty boolean property, is sufficient for OF
    # opt-in. A textual zero value would still be a production regression.
    require(COLD_FLAG not in nodes[NI_PATH], 'unverified cold-handoff flag present on production NI')
    return {'ni_path':NI_PATH, 'ni_enabled':True, 'statuses':statuses,
            'cold_handoff_property_present':False,
            'model':string_list(nodes['/']['model'])[0] if 'model' in nodes['/'] else None}


def with_old_flag(blob):
    tree=decode(blob)
    require(NI_PATH in tree['close_offsets'], 'negative control missing NI')
    strings=tree['strings']
    prop=struct.pack('>III',3,0,len(strings))
    at=tree['close_offsets'][NI_PATH]
    body=tree['structure'][:at]+prop+tree['structure'][at:]
    strings+=COLD_FLAG.encode()+b'\0'
    reserve=tree['reserve']
    off_struct=40+len(reserve)
    off_strings=off_struct+len(body)
    header=struct.pack('>10I',0xd00dfeed,off_strings+len(strings),off_struct,off_strings,
                       40,17,16,tree['header'][7],len(strings),len(body))
    return header+reserve+body+strings


def reject_old_flag(blob):
    mutant=with_old_flag(blob)
    try:
        validate(mutant)
    except DtbError as error:
        require('cold-handoff flag present' in str(error), f'negative control failed for wrong reason: {error}')
    else:
        raise DtbError('old cold-handoff negative control accepted')


def self_test():
    # A small binary fixture exercises decoding and the same semantic oracle.
    # Production proof still requires actual build outputs passed on the CLI.
    strings=b'compatible\0status\0'
    def begin(name):
        value=struct.pack('>I',1)+name.encode()+b'\0'
        return value+b'\0'*((-len(value))%4)
    def prop(offset,value):
        return struct.pack('>III',3,len(value),offset)+value+b'\0'*((-len(value))%4)
    body=begin('')+begin('soc')+begin('ethernet@4f4300000')
    body+=prop(0,NI_COMPATIBLE.encode()+b'\0')+prop(11,b'okay\0')
    body+=struct.pack('>4I',2,2,2,9)
    blob=struct.pack('>10I',0xd00dfeed,56+len(body)+len(strings),56,56+len(body),40,17,16,0,len(strings),len(body))
    blob+=bytes(16)+body+strings
    validate(blob)
    reject_old_flag(blob)
    disabled=blob.replace(b'okay\0',b'fail\0',1)
    try:
        validate(disabled)
    except DtbError as error:
        require('disabled' in str(error), 'disabled-node control failed for wrong reason')
    else:
        raise DtbError('disabled NI accepted')
    try:
        validate(blob[:-1])
    except DtbError:
        pass
    else:
        raise DtbError('truncated binary accepted')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true',help='Test the decoder/oracle using small binary fixtures')
    parser.add_argument('--output',type=Path,help='Write JSON evidence for real input DTBs')
    parser.add_argument('dtbs',type=Path,nargs='*')
    args=parser.parse_args()
    if not args.dtbs and not args.self_test:
        parser.error('compiled DTB input required (or --self-test for fixture validation only)')
    if args.output and not args.dtbs:
        parser.error('--output requires compiled DTB inputs')
    self_test()
    evidence=[]
    for path in args.dtbs:
        blob=path.read_bytes()
        record=validate(blob)
        reject_old_flag(blob)
        record.update({'file':str(path),'sha256':hashlib.sha256(blob).hexdigest(),
                       'old_cold_flag_negative_control_rejected':True})
        evidence.append(record)
        print(f'{path.name}: native NI enabled; production cold-handoff opt-in absent; old-flag negative control rejected')
    if args.output:
        args.output.write_text(json.dumps({'schema':1,'compiled_dtbs':len(evidence),'dtbs':evidence,
                                          'boot_success_proven':False,'hardware_forwarding_proven':False},indent=2)+'\n')
    print(f'Boot DTB oracle: {len(evidence)} compiled inputs validated; binary-fixture controls passed; boot_success_proven=false')


if __name__=='__main__':
    main()
