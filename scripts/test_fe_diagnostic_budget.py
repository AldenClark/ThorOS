#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Conservative byte proof for all five complete FE sysfs diagnostic pages.

This is not a simulated execution of the getters. It reads their actual format
literals and output-helper closure. All mutually exclusive branches/returns are
summed, numeric fields use their full printf type width (even boolean %u), and
known bounded strings use 64 bytes. Explicit production loop bounds multiply
their enclosed output. Unknown calls, loops, strings or formats fail closed.
The actual cached getter execution/locking is tested by test_l3_evidence.py.
"""
import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
PAGE_SIZE = 4096
STRING_MAX = 64


def uncomment(text):
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*'
    return re.sub(pattern, lambda m: ' ' * len(m[0]) if m[0].startswith('/') else m[0],
                  text, flags=re.S)


def masked(text):
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: ' ' * len(m[0]), text)


def balanced(text, start, opening='(', closing=')'):
    assert text[start] == opening
    depth = 1
    for end in range(start + 1, len(text)):
        depth += (text[end] == opening) - (text[end] == closing)
        if not depth:
            return end + 1
    raise AssertionError('unterminated production expression')


def arguments(text):
    clean = masked(text)
    depth = 0
    start = 0
    result = []
    for i, char in enumerate(clean):
        depth += (char in '([{') - (char in ')]}')
        if char == ',' and not depth:
            result.append(text[start:i].strip())
            start = i + 1
    assert depth == 0
    return result + [text[start:].strip()]


def literal(text):
    strings = re.findall(r'"(?:\\.|[^"\\])*"', text)
    assert strings and not re.sub(r'"(?:\\.|[^"\\])*"', '', text).strip(), \
        'dynamic or unsupported format literal'
    return ''.join(ast.literal_eval(value) for value in strings)


def format_bound(text):
    size = 0
    fields = []
    cursor = 0
    for match in re.finditer('%', text):
        if match.start() < cursor:
            continue
        size += len(text[cursor:match.start()].encode('utf-8'))
        field = re.match(r'%([-+#0 ]*)([0-9]*)(?:\.([0-9]+))?(ll|hh|[hljzt])?([diuxXosc%])',
                         text[match.start():])
        assert field, 'unbounded/unsupported printf format: ' + text[match.start():]
        flags, width, precision, length, kind = field.groups()
        if kind == '%':
            count = 1
        elif kind == 's':
            assert not length
            count = min(STRING_MAX, int(precision)) if precision is not None else STRING_MAX
        elif kind == 'c':
            count = 1
        else:
            bits = 64 if length in ('ll', 'l', 'j', 'z', 't') else 32
            if kind in 'di':
                count = len(str(-(1 << (bits - 1))))
            elif kind == 'u':
                count = len(str((1 << bits) - 1))
            elif kind in 'xX':
                count = bits // 4 + (2 if '#' in flags else 0)
            else:
                count = len(oct((1 << bits) - 1)[2:]) + ('#' in flags)
            if precision is not None:
                count = max(count, int(precision) + (kind in 'di'))
            if '+' in flags or ' ' in flags:
                count += 1
        size += max(count, int(width or 0))
        if kind != '%':
            fields.append(kind)
        cursor = match.start() + field.end()
    return size + len(text[cursor:].encode('utf-8')), fields


FILES = {
    'rtl_fe_state': 'rtl9617c-fe.c',
    'rtl_fe_resource_state': 'rtl9617c-fe.c',
    'rtl_fe_admission_state': 'rtl9617c-fe.c',
    'rtl_fe_l2_evidence': 'rtl9617c-fe.c',
    'rtl_fe_mce_inherited_evidence': 'rtl9617c-fe.c',
    'fe_mcast_stats': 'rtl9617c-fe.c',
    'fe_mdb_stats': 'rtl9617c-fe-mdb.h',
    'fe_mcast_evidence': 'rtl9617c-fe-mcast.h',
    'fe_bridge_stats': 'rtl9617c-fe-switch.h',
    'fe_bridge_evidence': 'rtl9617c-fe-switch.h',
}
sources = {name: uncomment((DRIVER / name).read_text()) for name in set(FILES.values())}
functions = {}
for name, filename in FILES.items():
    source = sources[filename]
    clean = masked(source)
    bodies = []
    for declaration in re.finditer(r'^(?:static )?ssize_t\s+' + name + r'\s*\(', clean, re.M):
        end = balanced(clean, clean.index('(', declaration.start()))
        start = end + len(clean[end:]) - len(clean[end:].lstrip())
        if clean[start] == ';':
            continue  # forward declaration, not a body
        assert clean[start] == '{'
        bodies.append(source[start + 1:balanced(clean, start, '{', '}') - 1])
    assert bodies, 'missing production definition: ' + name
    functions[name] = bodies


def enum_count(file, name, terminal):
    source = uncomment((DRIVER / file).read_text())
    body = re.search(r'enum\s+' + name + r'\s*\{([^}]+)\}', source).group(1)
    entries = [entry.strip() for entry in body.split(',') if entry.strip()]
    assert all(re.fullmatch(r'[A-Z_0-9]+', entry) for entry in entries)
    assert entries[-1] == terminal
    return len(entries) - 1


def constant(file, name):
    match = re.search(r'^#define\s+' + name + r'\s+(\d+)U?\s*$',
                      (DRIVER / file).read_text(), re.M)
    assert match, 'unrecognized production loop bound: ' + name
    return int(match[1])


register_source = uncomment((DRIVER / 'rtl9617c-l2-evidence.h').read_text())
register_macro = re.search(r'^#define RTL_L2_EVIDENCE_REGISTERS\(X\)(.*?)(?=\n\s*\n)',
                           register_source, re.M | re.S).group(1)
register_names = re.findall(r'X\([A-Z_0-9]+,\s*0x[0-9a-f]+U,\s*("[^"]+")\)', register_macro)
assert register_names and len(register_names) == register_macro.count('X(')
BOUNDS = {
    'FE_INSTALL_STAGE_COUNT': enum_count('rtl9617c-fe-observe.h', 'rtl_fe_install_stage', 'FE_INSTALL_STAGE_COUNT'),
    'RTL_L2_SHARED_COUNT': enum_count('rtl9617c-l2-domain.h', 'rtl_l2_shared_kind', 'RTL_L2_SHARED_COUNT'),
    'RTL_L2_EVIDENCE_REG_COUNT': len(register_names),
    'RTL_L2_EVIDENCE_LAN_PORTS': constant('rtl9617c-l2-evidence.h', 'RTL_L2_EVIDENCE_LAN_PORTS'),
    'FE_INTERFACES': constant('rtl9617c-fe.c', 'FE_INTERFACES'),
    'FE_LAN_PORTS': constant('rtl9617c-fe.c', 'FE_LAN_PORTS'),
}
# Every string source used by these getters is an enum/configuration label,
# not a user string. Check the conservative 64-byte bound against production.
for file in ('rtl9617c-fe-observe.h', 'rtl9617c-fe-mdb.h', 'rtl9617c-fe-switch-hw.h'):
    for value in re.findall(r'"(?:\\.|[^"\\])*"', uncomment((DRIVER / file).read_text())):
        decoded = ast.literal_eval(value)
        if '\n' not in decoded and '%' not in decoded:
            assert len(decoded.encode('utf-8')) <= STRING_MAX, (file, decoded)
assert all(len(ast.literal_eval(name).encode('utf-8')) <= STRING_MAX for name in register_names)

NO_OUTPUT = {
    'if', 'for', 'READ_ONCE', 'mutex_lock', 'mutex_trylock', 'mutex_unlock',
    'list_for_each_entry', 'jiffies_to_msecs', 'fe_read', 'FE_LAN_RX_CTRL', 'BIT',
    'rtl_fabric_native_mtu_compatible', 'rtl_l2_shared_capacity',
    'rtl_l2_shared_leased', 'rtl_l2_shared_available', 'rtl_fe_install_stage_name',
    'rtl_fe_fdb_mode_reason_name',
    'RTL_L2_EVIDENCE_NAME', 'RTL_L2_EVIDENCE_REGISTERS', 'ktime_get_ns',
    'spin_lock_irqsave', 'spin_unlock_irqrestore', 'rtl_l2_evidence_read',
    'rtl_mcast_handoff_sample',
    'rtl9617c_switch_guard_generation', 'fe_switch_hw_reason_name',
    'fe_switch_hw_reason_text', 'fe_mdb_reason_name',
}
STRING_CALLS = {'rtl_fe_install_stage_name', 'rtl_fe_fdb_mode_reason_name', 'fe_mdb_reason_name',
                'fe_switch_hw_reason_text', 'fe_switch_hw_reason_name'}


def loop_ranges(body):
    clean = masked(body)
    assert not re.search(r'\b(while|do|goto|switch)\b', clean), 'unrecognized control flow'
    ranges = []
    for loop in re.finditer(r'\b(for|list_for_each_entry)\s*\(', clean):
        end = balanced(clean, clean.index('(', loop.start()))
        header = re.sub(r'\s+', '', clean[clean.index('(', loop.start()) + 1:end - 1])
        if loop[1] == 'for':
            match = re.fullmatch(r'(i|port)=0;\1<([A-Z_0-9]+);\1\+\+', header)
            assert match and match[2] in BOUNDS, 'unknown loop: ' + header
            count = BOUNDS[match[2]]
        else:
            assert header in ('flow,&fe->flows,list', 'flow,&fe->retries,retry'), header
            count = None  # Existing counting walks MUST stay non-emitting.
        start = end + len(clean[end:]) - len(clean[end:].lstrip())
        # The one existing list walk has `if (flow->published) { ... }`
        # as its unbraced loop body. It may only count, never emit output.
        conditional = re.match(r'if\s*\(flow->published\)\s*\{', clean[start:])
        if conditional:
            assert count is None
            opening = clean.index('{', start)
            finish = balanced(clean, opening, '{', '}')
            ranges.append((start, finish, count))
            continue
        if clean[start] == '{':
            finish = balanced(clean, start, '{', '}')
        else:
            depth = 0
            for finish in range(start, len(clean)):
                char = clean[finish]
                assert char not in '{}', 'new compound loop body requires braces'
                depth += (char in '([') - (char in ')]')
                if char == ';' and not depth:
                    finish += 1
                    break
            else:
                raise AssertionError('unterminated loop body')
            assert not re.match(r'\s*else\b', clean[finish:]), 'new loop conditional requires braces'
        ranges.append((start, finish, count))
    return ranges


def function_bound(name, stack=()):
    assert name not in stack, 'recursive output helper'
    variants = []
    for body in functions[name]:
        clean = masked(body)
        ranges = loop_ranges(body)
        total = 0
        for call in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', clean):
            called = call[1]
            assert called in NO_OUTPUT or called in functions or called in ('scnprintf', 'sysfs_emit'), \
                'unknown diagnostic helper: ' + called
            if called in NO_OUTPUT:
                continue
            end = balanced(clean, clean.index('(', call.start()))
            args = arguments(body[clean.index('(', call.start()) + 1:end - 1])
            if called in functions:
                cost = function_bound(called, stack + (name,))
            else:
                slot = 2 if called == 'scnprintf' else 1
                fmt = literal(args[slot])
                cost, fields = format_bound(fmt)
                assert len(fields) == len(args) - slot - 1, 'format argument count changed'
                for field, argument in zip(fields, args[slot + 1:]):
                    if field == 's':
                        assert (re.sub(r'\s+', '', argument) == 'names[i]' or
                                any(re.search(r'\b' + provider + r'\s*\(', argument)
                                    for provider in STRING_CALLS)), 'unknown %s source: ' + argument
            for start, finish, count in ranges:
                if start <= call.start() < finish:
                    assert count is not None, 'unbounded counting walk gained output'
                    cost *= count
            total += cost
        variants.append(total)
    return max(variants)


PAGES = {
    'l2_state': 'rtl_fe_state', 'l2_resources': 'rtl_fe_resource_state',
    'l3_admission': 'rtl_fe_admission_state', 'l2_evidence': 'rtl_fe_l2_evidence',
    'mce_inherited': 'rtl_fe_mce_inherited_evidence',
}
budgets = {page: function_bound(function) for page, function in PAGES.items()}
for page, size in budgets.items():
    assert size < PAGE_SIZE, f'{page}: {size} output bytes + NUL exceeds {PAGE_SIZE}'

# Independent negative controls: a literal/width increase must affect the byte
# proof; newly added helper/loop/output in an unbounded walk must fail closed.
original = functions['rtl_fe_resource_state']
mutations = (
    original[0].replace('schema=1 available=1 cached=1', 'X' * PAGE_SIZE),
    original[0].replace('l2_owner_sealed=%u', 'l2_owner_sealed=%5000u'),
    original[0] + '\nlength+=fe_new_diagnostic(fe,buffer,PAGE_SIZE);',
    original[0] + '\nfor(i=0;i<NEW_UNKNOWN_BOUND;i++) length+=scnprintf(buffer,PAGE_SIZE,"x");',
    original[0] + '\nlist_for_each_entry(flow,&fe->flows,list) length+=scnprintf(buffer,PAGE_SIZE,"x");',
    original[0].replace('l2_owner_sealed=%u', 'l2_owner_sealed=%n'),
)
for mutation in mutations:
    functions['rtl_fe_resource_state'] = [mutation]
    try:
        assert function_bound('rtl_fe_resource_state') < PAGE_SIZE
    except AssertionError:
        pass
    else:
        raise AssertionError('diagnostic byte-budget negative control survived')
functions['rtl_fe_resource_state'] = original
print('FE diagnostic upper bounds (bytes excluding NUL; all branches summed, %s <= 64): ' +
      ', '.join(f'{page}={size}' for page, size in budgets.items()))
print('Production loop bounds: ' + ', '.join(f'{name}={count}' for name, count in BOUNDS.items()))
print('All five complete pages fit 4096 bytes; six independent negative controls rejected')
