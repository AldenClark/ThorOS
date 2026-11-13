#!/usr/bin/env python3
"""Run the real FE physical-parent-ID encoder without dereferencing MMIO."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c"
source = SOURCE.read_text()
start = re.search(r"^int rtl_fe_get_port_parent_id\(", source, re.M).start()
end = source.index("\n}", start) + 2
production = source[start:end]

COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
#define READ_ONCE(value) (value)
#define IORESOURCE_MEM 0x200
struct resource { u64 start; };
struct platform_device { struct resource resource; bool present; };
struct rtl_fe { bool shutting_down; struct platform_device *device; };
struct netdev_phys_item_id { unsigned char id[32], id_len; };
static struct platform_device *to_platform_device(struct platform_device *device) { return device; }
static struct resource *platform_get_resource(struct platform_device *device, unsigned int kind, unsigned int index) {
 assert(kind == IORESOURCE_MEM && index == 0);
 return device->present ? &device->resource : NULL;
}
static void put_unaligned_be64(u64 value, void *pointer) {
 unsigned char *bytes = pointer;
 for (unsigned int i = 0; i < 8; i++) bytes[i] = value >> (56 - i * 8);
}
'''
TEST = r'''
int main(void) {
 struct platform_device platform = {.resource={.start=0x4f4000000}, .present=true};
 struct rtl_fe first = {.device=&platform}, second = {.device=&platform};
 struct netdev_phys_item_id a, b, marker;
 memset(&marker, 0xa5, sizeof(marker)); a = b = marker;
 assert(!rtl_fe_get_port_parent_id(&first, &a));
 assert(!rtl_fe_get_port_parent_id(&second, &b));
 assert(a.id_len == 8 && !memcmp(a.id, "\x00\x00\x00\x04\xf4\x00\x00\x00", 8));
 assert(!memcmp(a.id, b.id, 8)); /* Per-port owners, one physical switch. */
 for (unsigned int bit = 0; bit < 64; bit++) {
  platform.resource.start = UINT64_C(1) << bit; a = marker;
  assert(!rtl_fe_get_port_parent_id(&first, &a));
  for (unsigned int byte = 0; byte < 8; byte++)
   assert(a.id[byte] == (byte == 7 - bit / 8 ? 1U << (bit % 8) : 0));
  for (unsigned int byte = 8; byte < sizeof(a.id); byte++) assert(a.id[byte] == marker.id[byte]);
 }
 platform.resource.start = 0x4f5000000;
 assert(!rtl_fe_get_port_parent_id(&first, &a)); assert(memcmp(a.id, b.id, 8));
 a = marker; first.shutting_down = true;
 assert(rtl_fe_get_port_parent_id(&first, &a) == -EOPNOTSUPP && !memcmp(&a, &marker, sizeof(a)));
 assert(rtl_fe_get_port_parent_id(NULL, &a) == -EOPNOTSUPP && !memcmp(&a, &marker, sizeof(a)));
 first.shutting_down = false; platform.present = false;
 assert(rtl_fe_get_port_parent_id(&first, &a) == -ENODEV && !memcmp(&a, &marker, sizeof(a)));
 puts("L2 physical parent: resource-address identity shared across ports; 64 address bits, big-endian encoding, distinct devices and shutdown/error non-mutation passed");
 return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="l2-parent-id-") as directory:
    temporary = Path(directory)
    (temporary / "test.c").write_text(COMMON + production + TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    str(temporary / "test.c"), "-o", str(temporary / "test")], check=True)
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    subprocess.run([str(temporary / "test")], check=True, env=environment)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-parent-id.json").write_text(json.dumps({
    "production_function_sha256": hashlib.sha256(production.encode()).hexdigest(),
    "tested_address_bits": 64,
    "hardware_verified": False,
}, indent=2) + "\n")
