#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

parts=(hero leak stores degraded limits install script)

assemble() {
  cat site-src/head.html
  printf '<style>\n'
  cat site-src/style/base.css site-src/style/sections.css
  printf '</style>\n'
  for part in "${parts[@]}"; do cat "site-src/$part.html"; done
}

case "${1:-}" in
  "") assemble > site/index.html ;;
  --check)
    if ! assemble | cmp -s - site/index.html; then
      echo "site/index.html differs from what site-src/ assembles to; run scripts/site.sh" >&2
      exit 1
    fi
    ;;
  *) echo "usage: scripts/site.sh [--check]" >&2; exit 2 ;;
esac
