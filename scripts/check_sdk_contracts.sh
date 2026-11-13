#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Reproducible external vendor-source oracles; no SDK code is vendored or run
# against a device. Test inputs are pinned again by SHA256 inside the oracles.
set -euo pipefail
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
mkdir -p "$project/artifacts"
work=$(mktemp -d "$project/artifacts/sdk-contracts.XXXXXX")
sdk_pin=8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0
register_pin=5090fbcb6ba743dd7b1314811ef557bad0460147
sdk_path=ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c
mkdir -p "$work/sdk/$sdk_path/include"
fetch() {
    curl --fail --location --silent --show-error --retry 3 \
        --connect-timeout 15 --max-time 180 "$1" --output "$2"
}
for file in include/aal_common.h aal_common.c include/aal_hash.h aal_hash.c aal_l3qm.c \
            include/aal_fdb.h aal_fdb.c include/aal_mcast.h include/aal_port.h \
            aal_l2_classification.c include/aal_l2_classification.h include/aal_arb.h \
            include/aal_l2_qos.h include/aal_l2_vlan.h \
            include/aal_l3_cls.h include/aal_l3fe.h \
            include/aal_l2_specpkt.h aal_l2_specpkt.c; do
    fetch "https://raw.githubusercontent.com/jameywine/ca-network-drivers/$sdk_pin/$sdk_path/$file" \
        "$work/sdk/$sdk_path/$file"
done
fetch "https://raw.githubusercontent.com/jameywine/GPL-for-GP3000/$register_pin/linux-5.10.x/include/soc/cortina/rtl8277c_registers.h" \
    "$work/rtl8277c_registers.h"
cd "$project"
python3 scripts/test_fe_sdk_contract.py --sdk "$work/sdk"
python3 scripts/test_fe_register_contract.py --registers "$work/rtl8277c_registers.h"
python3 scripts/test_l2_sdk_contract.py --sdk "$work/sdk" --registers "$work/rtl8277c_registers.h"
python3 scripts/test_l2_hardware_recipe.py --registers "$work/rtl8277c_registers.h"
python3 scripts/test_pon_sdk_registers.py --sdk-header "$work/rtl8277c_registers.h"
python3 scripts/test_qm_sdk_registers.py --sdk-header "$work/rtl8277c_registers.h" \
    --sdk-qm "$work/sdk/$sdk_path/aal_l3qm.c"
printf 'PASS: external pinned SDK source/register contracts. This is not a silicon throughput test.\n'
