#!/bin/sh
set -eu
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
  printf 'Rust/Cargo is not installed. Install via https://rustup.rs/ first.\n' >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin) ;;
  *) printf 'Run this script on macOS, not Linux.\n' >&2; exit 1 ;;
esac

cargo build --release --locked
mkdir -p dist
cp target/release/tyfza1-netwatch dist/tyfza1-netwatch
cp sites.txt dist/sites.txt
cp README.md dist/README.md
printf '\nBuilt %s/dist/tyfza1-netwatch (%s)\n' "$(pwd)" "$(file dist/tyfza1-netwatch)"
printf 'Run: ./dist/tyfza1-netwatch --router 192.168.1.1 --user root\n'

