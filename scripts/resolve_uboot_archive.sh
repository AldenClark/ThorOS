#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Use the source version selected by the locked OpenWrt checkout, not the
# separately pinned U-Boot host FIT-tool version.
set -eu

TREE=${1:?Usage: resolve_uboot_archive.sh openwrt-tree}
PACKAGE=$TREE/package/boot/uboot-tools/Makefile
VERSION=$(sed -n 's/^PKG_VERSION:=//p' "$PACKAGE")
HASH=$(sed -n 's/^PKG_HASH:=//p' "$PACKAGE")
case "$VERSION" in
    ''|*[!a-zA-Z0-9._-]*)
        echo "Invalid OpenWrt U-Boot source version: $VERSION" >&2
        exit 1
        ;;
esac
case "$HASH" in
    ''|*[!0-9a-f]*)
        echo 'Invalid OpenWrt U-Boot source hash' >&2
        exit 1
        ;;
esac
if [ "${#HASH}" -ne 64 ]; then
    echo 'Invalid OpenWrt U-Boot SHA-256 length' >&2
    exit 1
fi

ARCHIVE=$TREE/dl/u-boot-$VERSION.tar.bz2
if [ ! -f "$ARCHIVE" ]; then
    echo "Missing OpenWrt U-Boot source: $ARCHIVE" >&2
    exit 1
fi
printf '%s  %s\n' "$HASH" "$ARCHIVE" | sha256sum -c - >&2
printf '%s\n' "$ARCHIVE"
