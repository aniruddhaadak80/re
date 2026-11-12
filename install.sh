#!/bin/sh
# Install the single binary CLI from a GitHub release and check its SHA-256 before it is installed.
#
#   curl -fsSL https://raw.githubusercontent.com/aniruddhaadak80/re/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version 1.2.0 --dir /usr/local/bin
#
# Options (or the environment variable in brackets):
#   --version V     release to install, default the latest            [INSTALL_VERSION]
#   --dir D         folder for the binary, default ~/.local/bin       [INSTALL_DIR]
#   --repo O/R      GitHub repository, default aniruddhaadak80/re     [INSTALL_REPO]
#   --alias NAME    also link the binary under NAME (repeatable)      [INSTALL_ALIASES, space separated]
#   --dry-run       print what would happen and stop
# INSTALL_BASE_URL replaces https://github.com/<repo>/releases (mirrors and tests).
#
# The binary name is not fixed here: it is read from the release's SHA256SUMS file, whose entries are
# named <bin>-<os>-<arch>. Nothing runs before the whole file is downloaded (main is called last).
set -eu

say() { printf '%s\n' "$*" >&2; }
fail() { say "install failed: $*"; exit 1; }

main() {
  version="${INSTALL_VERSION:-}"
  dir="${INSTALL_DIR:-$HOME/.local/bin}"
  repo="${INSTALL_REPO:-aniruddhaadak80/re}"
  aliases="${INSTALL_ALIASES:-}"
  dry=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || fail "--version needs a value"; version="$2"; shift 2 ;;
      --dir) [ $# -ge 2 ] || fail "--dir needs a value"; dir="$2"; shift 2 ;;
      --repo) [ $# -ge 2 ] || fail "--repo needs a value"; repo="$2"; shift 2 ;;
      --alias) [ $# -ge 2 ] || fail "--alias needs a value"; aliases="$aliases $2"; shift 2 ;;
      --dry-run) dry=true; shift ;;
      -h|--help) sed -n '2,20p' "$0" 2>/dev/null || true; exit 0 ;;
      *) fail "unknown option $1" ;;
    esac
  done
  case "$repo" in */*) ;; *) fail "--repo must look like owner/name" ;; esac
  case "$version" in ''|[0-9]*.[0-9]*.[0-9]*|v[0-9]*.[0-9]*.[0-9]*) ;; *) fail "version must look like 1.2.3" ;; esac

  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) fail "this script supports Linux and macOS; on Windows use install.ps1" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=x64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) fail "no binary is published for CPU $(uname -m)" ;;
  esac

  base="${INSTALL_BASE_URL:-https://github.com/$repo/releases}"
  if [ -n "$version" ]; then
    case "$version" in v*) tag="$version" ;; *) tag="v$version" ;; esac
    url="$base/download/$tag"
  else
    url="$base/latest/download"
  fi

  if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --retry 3 --proto '=https,http' -o "$2" "$1"; }
  elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
  else
    fail "curl or wget is needed"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha() { sha256sum "$1" | cut -d ' ' -f 1; }
  elif command -v shasum >/dev/null 2>&1; then
    sha() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
  else
    fail "sha256sum or shasum is needed to check the download"
  fi

  tmp="$(mktemp -d 2>/dev/null || mktemp -d -t install)"
  trap 'rm -rf "$tmp"' EXIT INT TERM
  fetch "$url/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download $url/SHA256SUMS"

  # pick the line for this platform: "<sha256>  <bin>-<os>-<arch>"
  line="$(grep -E "^[0-9a-f]{64}  [A-Za-z0-9._-]+-$os-$arch\$" "$tmp/SHA256SUMS" | head -n 1 || true)"
  [ -n "$line" ] || fail "the release has no binary for $os-$arch"
  want="$(printf '%s' "$line" | cut -d ' ' -f 1)"
  asset="$(printf '%s' "$line" | cut -d ' ' -f 3)"
  bin="${asset%-$os-$arch}"
  case "$bin" in ''|*/*|.*) fail "unexpected asset name $asset" ;; esac

  say "installing $bin ($asset) from $url into $dir"
  if [ "$dry" = true ]; then
    say "dry run: would download $url/$asset, check sha256 $want, and write $dir/$bin"
    exit 0
  fi

  fetch "$url/$asset" "$tmp/$asset" || fail "could not download $url/$asset"
  got="$(sha "$tmp/$asset")"
  [ "$got" = "$want" ] || fail "sha256 mismatch for $asset: expected $want, got $got. Nothing was installed."
  say "sha256 ok: $got"

  mkdir -p "$dir"
  chmod 755 "$tmp/$asset"
  if [ "$os" = macos ] && command -v xattr >/dev/null 2>&1; then xattr -d com.apple.quarantine "$tmp/$asset" 2>/dev/null || true; fi
  mv -f "$tmp/$asset" "$dir/$bin"
  for a in $aliases; do
    case "$a" in ''|*/*|.*) fail "bad alias name $a" ;; esac
    ln -sf "$bin" "$dir/$a"
  done

  if v="$("$dir/$bin" --version 2>/dev/null)"; then say "installed $bin $v at $dir/$bin"; else fail "$dir/$bin did not run"; fi
  case ":$PATH:" in *":$dir:"*) ;; *) say "note: $dir is not on your PATH. Add it, for example: export PATH=\"$dir:\$PATH\"" ;; esac
}

main "$@"
