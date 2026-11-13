# SPDX-License-Identifier: GPL-2.0-only
# Unmodified nand_upgrade_tar() from openwrt/openwrt
# ada52cc7ed401153a8d0b026d1edf918bfc04c45
# package/base-files/files/lib/upgrade/nand.sh (for failure-injection tests).

# Write images in the TAR file to MTD partitions and/or UBI volumes as required
nand_upgrade_tar() {
	local tar_file="$1"
	local cmd="${2:-cat}"
	local jffs2_markers="${CI_JFFS2_CLEAN_MARKERS:-0}"

	# WARNING: This fails if tar contains more than one 'sysupgrade-*' directory.
	local board_dir="$($cmd < "$tar_file" | tar tf - | grep -m 1 '^sysupgrade-.*/$')"
	board_dir="${board_dir%/}"

	local kernel_mtd kernel_length
	if [ "$CI_KERNPART" != "none" ]; then
		kernel_mtd="$(find_mtd_index "$CI_KERNPART")"
		kernel_length=$( ($cmd < "$tar_file" | tar xOf - "$board_dir/kernel" | wc -c) 2> /dev/null)
		[ "$kernel_length" = 0 ] && kernel_length=
	fi
	local rootfs_length=$( ($cmd < "$tar_file" | tar xOf - "$board_dir/root" | wc -c) 2> /dev/null)
	[ "$rootfs_length" = 0 ] && rootfs_length=
	local rootfs_type
	[ "$rootfs_length" ] && rootfs_type="$(identify_tar "$tar_file" "$cmd" "$board_dir/root")"

	# If CI_SKIP_KERNEL_MTD is set, ignore any potential kernel MTD partition that was found.
	# This is needed if there's an MTD partition with the same name as the kernel's UBI volume.
	[ "${CI_SKIP_KERNEL_MTD:-}" ] && kernel_mtd=

	local ubi_kernel_length
	if [ "$kernel_length" ]; then
		if [ "$kernel_mtd" ]; then
			# On some devices, the raw kernel and ubi partitions overlap.
			# These devices brick if the kernel partition is erased.
			# Hence only invalidate kernel for now.
			dd if=/dev/zero bs=4096 count=1 2> /dev/null | \
				mtd write - "$CI_KERNPART"
		else
			ubi_kernel_length="$kernel_length"
		fi
	fi

	local has_env=0
	nand_upgrade_prepare_ubi "$rootfs_length" "$rootfs_type" "$ubi_kernel_length" "$has_env" || return 1

	if [ "$rootfs_length" ]; then
		local ubidev="$( nand_find_ubi "${CI_ROOT_UBIPART:-$CI_UBIPART}" )"
		local root_ubivol="$( nand_find_volume $ubidev "$CI_ROOTPART" )"
		$cmd < "$tar_file" | tar xOf - "$board_dir/root" | \
			ubiupdatevol /dev/$root_ubivol -s "$rootfs_length" -
	fi
	if [ "$kernel_length" ]; then
		if [ "$kernel_mtd" ]; then
			if [ "$jffs2_markers" = 1 ]; then
				flash_erase -j "/dev/mtd${kernel_mtd}" 0 0
				$cmd < "$tar_file" | tar xOf - "$board_dir/kernel" | \
					nandwrite "/dev/mtd${kernel_mtd}" -
			else
				$cmd < "$tar_file" | tar xOf - "$board_dir/kernel" | \
					mtd write - "$CI_KERNPART"
			fi
		else
			local ubidev="$( nand_find_ubi "${CI_KERN_UBIPART:-$CI_UBIPART}" )"
			local kern_ubivol="$( nand_find_volume $ubidev "$CI_KERNPART" )"
			$cmd < "$tar_file" | tar xOf - "$board_dir/kernel" | \
				ubiupdatevol /dev/$kern_ubivol -s "$kernel_length" -
		fi
	fi

	return 0
}
