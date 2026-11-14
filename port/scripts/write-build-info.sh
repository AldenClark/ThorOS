#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Deterministic public source identity; never serialize the environment or keys.
set -eu
umask 022
PROJECT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
OUTPUT=${1:?Usage: write-build-info.sh /path/to/thoros-build-info}
VERSION=$(cat "$PROJECT/VERSION")
case "$VERSION" in
    ''|*[!a-zA-Z0-9._+-]*) echo 'Invalid public firmware version' >&2; exit 1 ;;
esac
[ "${#VERSION}" -le 64 ] || { echo 'Firmware version too long' >&2; exit 1; }
LOCK_HASH=$(sha256sum < "$PROJECT/port/sources.lock.json")
LOCK_HASH=${LOCK_HASH%% *}

COMMIT=unknown
DIRTY=unknown
TOP=$(git -C "$PROJECT" rev-parse --show-toplevel 2>/dev/null || true)
# Source archives can live inside another repository. Never attribute them to
# that unrelated parent repository; linked worktrees, on the other hand, work.
if [ "$TOP" = "$PROJECT" ]; then
    REVISION=$(git -C "$PROJECT" rev-parse --verify HEAD 2>/dev/null || true)
    case "$REVISION" in
        ''|*[!0-9a-f]*) ;;
        *)
            if [ "${#REVISION}" = 40 ] || [ "${#REVISION}" = 64 ]; then
                COMMIT=$REVISION
                # Build trees/reference material are not ThorOS source. They
                # are either pinned by sources.lock.json or deliberately not
                # included in this source-identity stamp.
                STATUS=$(git -C "$PROJECT" status --porcelain --untracked-files=normal -- . \
                    ':(exclude)sources' ':(exclude)artifacts' ':(exclude)logs' \
                    ':(exclude)evidence' ':(exclude)analysis')
                DIRTY=0
                [ -z "$STATUS" ] || DIRTY=1
            fi
            ;;
    esac
fi

mkdir -p -- "$(dirname -- "$OUTPUT")"
TEMPORARY=$(mktemp "${OUTPUT}.XXXXXX")
trap 'rm -f -- "$TEMPORARY"' 0
trap 'exit 1' 1 2 15
{
    printf 'schema=1\n'
    printf 'project_version=%s\n' "$VERSION"
    printf 'project_commit=%s\n' "$COMMIT"
    printf 'project_dirty=%s\n' "$DIRTY"
    printf 'sources_lock_sha256=%s\n' "$LOCK_HASH"
} > "$TEMPORARY"
chmod 0644 "$TEMPORARY"
mv -f -- "$TEMPORARY" "$OUTPUT"
