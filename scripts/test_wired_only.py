#!/usr/bin/env python3
"""Check that TYFZA1 release images cannot accidentally regain WLAN support."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "port/overlay/target/linux/rtl9617c"
PACKAGE = ROOT / "port/packages/tyfza1-pon-control/files"
LUCI = ROOT / "port/packages/luci-app-tyfza1-pon"


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


class WiredOnly(unittest.TestCase):
    def test_kernel_and_board(self):
        config = read("port/overlay/target/linux/rtl9617c/config-6.18")
        for name in ("WLAN", "CFG80211", "MAC80211"):
            self.assertIn(f"# CONFIG_{name} is not set", config)
            self.assertNotRegex(config, rf"(?m)^CONFIG_{name}=[ym]$")
        self.assertNotRegex(config, r"(?m)^CONFIG_RTL_AX_AP=[ym]$")

        dts = read("port/overlay/target/linux/rtl9617c/dts/rtl9617c-tyfza1-ubi.dts")
        for controller in ("pcie0", "pcie1"):
            self.assertRegex(dts, rf"&{controller}\s*\{{\s*status\s*=\s*\"disabled\";\s*\}}")
        # The PHY provider also owns SGMII (2.5G) and USB control registers.
        self.assertIn("pcie_controls:", read("port/overlay/target/linux/rtl9617c/dts/rtl9617c-tyfza1-pcie.dts"))
        self.assertTrue((TARGET / "dts/rtl9617c-tyfza1-ubi-2p5g.dts").exists())
        self.assertFalse(list((TARGET / "files-6.18/drivers/net/wireless").rglob("*.*")))
        self.assertFalse((ROOT / "port/pe/rtl9617c-radio-wd.c").exists())
        self.assertFalse((TARGET / "files-6.18/drivers/net/ethernet/realtek/rtl9617c-wifi.c").exists())
        self.assertFalse((TARGET / "files-6.18/include/linux/rtl9617c-wifi.h").exists())
        self.assertFalse(list((TARGET / "patches-6.18").glob("*mac80211*")))
        self.assertFalse(list((TARGET / "patches-6.18").glob("*wifi*")))
        self.assertFalse(list((TARGET / "patches-6.18").glob("*radio*")))
        self.assertTrue((TARGET / "patches-6.18/202-native-fe-ingress.patch").exists())
        for file in (TARGET / "files-6.18/drivers/net/ethernet/realtek").glob("rtl9617c-*.[ch]"):
            self.assertNotRegex(file.read_text(), r"(?i)rtl_wifi|rtl9617c_wifi|wifi_(memory|epp|dma)|RTL_QM_PE_(BUFFERS|EQ)")

    def test_packages_and_build(self):
        config = read("port/configs/tyfza1-boot.config")
        forbidden = ("kmod-cfg80211", "kmod-mac80211", "kmod-rtl-ax-ap",
                     "iw", "iwinfo", "rpcd-mod-iwinfo", "hostapd",
                     "wpad-basic-mbedtls", "wpad-mbedtls", "wifi-scripts", "wireless-regdb")
        device = read("port/overlay/target/linux/rtl9617c/image/Makefile")
        for package in forbidden:
            self.assertNotIn(f"CONFIG_PACKAGE_{package}=y", config)
            self.assertIn(f"-{package}", device)
        self.assertIn("kmod-cfg80211|kmod-mac80211", read("port/scripts/build.sh"))
        self.assertNotIn("build_pe_radio_wd", read("port/scripts/build.sh"))
        self.assertNotIn("prepare_wifi_runtime", read("port/scripts/build.sh"))
        self.assertNotIn("rtl-ax-ap", read("port/overlay/target/linux/rtl9617c/modules.mk"))
        self.assertFalse((TARGET / "base-files/etc/board.d/03_wireless").exists())
        self.assertFalse((TARGET / "base-files/etc/uci-defaults/92-tyfza1-wireless-country").exists())
        self.assertNotIn("import_radio", (PACKAGE / "factory.uc").read_text())
        self.assertNotIn("wifi_leds", (PACKAGE / "leds.uc").read_text())
        self.assertNotIn("wifi-scripts", read("port/overlay/target/linux/rtl9617c/base-files/etc/uci-defaults/99-tyfza1-platform-packages"))

    def test_luci_wired_only(self):
        patch = read("port/luci-patches/116-tyfza1-wired-only-ui.patch")
        components = read("port/luci-patches/117-tyfza1-wired-only-components.patch")
        for entry in ('"admin/network/wireless"', '"admin/status/realtime/wireless"',
                      '"admin/status/channel_analysis"'):
            self.assertRegex(patch, r"(?m)^-\s*" + re.escape(entry))
        self.assertIn("-LUCI_DEPENDS:=+luci-base +libiwinfo +rpcd-mod-iwinfo", patch)
        self.assertIn("+LUCI_DEPENDS:=+luci-base", patch)
        self.assertIn("-LUCI_DEPENDS:=+luci-base +rpcd-mod-iwinfo", patch)
        self.assertIn("view/network/wireless.js", read("scripts/prepare_luci_feeds.sh"))
        self.assertIn("view/status/include/60_wifi.js", read("scripts/prepare_luci_feeds.sh"))
        self.assertIn('-\t"luci-mod-status-index-wifi"', components)
        self.assertIn("luci-mod-network-wireless.json", components)
        self.assertIn("tools/network.js", components)
        ui = (LUCI / "htdocs/luci-static/resources/tyfza1/ui.js").read_text()
        overview = (LUCI / "htdocs/luci-static/resources/view/tyfza1/overview.js").read_text()
        acl = (LUCI / "root/usr/share/rpcd/acl.d/luci-app-tyfza1-pon.json").read_text()
        for data in (ui, overview, acl):
            self.assertNotRegex(data, r"(?i)wireless|getWirelessDevices|iwinfo|wifi")

    def test_actions_do_not_use_removed_tests(self):
        for name in ("pr-checks", "network-feedback-checks", "build-release"):
            yaml = read(f".github/workflows/{name}.yml")
            self.assertNotRegex(yaml, r"(?i)test_(wifi|radio|sta|pe)|build_pe_radio|forward_hash")
            for script in re.findall(r"python3\s+(scripts/[\w/-]+\.py)", yaml):
                self.assertTrue((ROOT / script).is_file(), f"missing CI test: {script}")

    def test_runtime_installs_only_pon_serdes(self):
        modes = ("epon", "epon_d10g", "epon_bi10g", "gpon", "xgpon", "xgspon")
        with tempfile.TemporaryDirectory(prefix="tyfza1-wired-runtime-") as temporary:
            inputs, output = Path(temporary) / "inputs", Path(temporary) / "output"
            firmware = inputs / "lib/firmware/realtek/rtl9617c"
            firmware.mkdir(parents=True)
            for mode in modes:
                (firmware / f"pon_serdes_{mode}.bin").write_bytes(b"test-serdes")
            (firmware / "rtl8852ce-wifi.bin").write_bytes(b"must-not-copy")
            (inputs / "lib/firmware/regulatory.db").write_bytes(b"must-not-copy")
            subprocess.run([sys.executable, str(ROOT / "tools/install_runtime_inputs.py"),
                            str(inputs), str(output)], check=True, capture_output=True)
            actual = list((output / "lib/firmware").rglob("*"))
            actual_files = {file.name for file in actual if file.is_file()}
            self.assertEqual(actual_files, {f"pon_serdes_{mode}.bin" for mode in modes})
            self.assertTrue((output / "etc/config/pon").is_file())


if __name__ == "__main__":
    unittest.main()
