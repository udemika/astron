#!/bin/bash
# Ubuntu / Debian one-command installer, updater, and uninstaller for AstraG / Astasy (Pure Native C Single Binary).
# Zero Python runtime dependencies, zero /opt/astrag extraction — identical in simplicity to Cesbo Astra.
set -euo pipefail

START=true
UNINSTALL=false
PURGE=false
FORCE_BUILD=false
CUSTOM_PORT="${ASTRA_PORT:-8000}"
REPO_URL="${ASTRA_REPO_URL:-https://github.com/udemika/astron.git}"
RAW_URL="${ASTRA_RAW_URL:-https://raw.githubusercontent.com/udemika/astron/main/astrag}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --start|--restart|--update) START=true; shift ;;
        --no-start) START=false; shift ;;
        --uninstall|--remove) UNINSTALL=true; shift ;;
        --purge) UNINSTALL=true; PURGE=true; shift ;;
        --build|--source|--compile) FORCE_BUILD=true; shift ;;
        --apt|--system|--binary|--bin|--single-binary) shift ;;
        --mode)
            if [ "$#" -lt 2 ]; then echo "Missing value after --mode" >&2; exit 2; fi
            shift 2 ;;
        --port)
            if [ "$#" -lt 2 ]; then echo "Missing port number after --port" >&2; exit 2; fi
            CUSTOM_PORT="$2"; shift 2 ;;
        --repo)
            if [ "$#" -lt 2 ]; then echo "Missing repository URL after --repo" >&2; exit 2; fi
            REPO_URL="$2"; shift 2 ;;
        *)
            echo "Usage: sudo bash install.sh [--start|--no-start|--uninstall|--purge] [--build] [--port PORT] [--repo GIT_URL]" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (sudo)." >&2
    exit 1
fi

if "$UNINSTALL"; then
    if [ -x /usr/bin/astrag ]; then
        if "$PURGE"; then
            /usr/bin/astrag remove --purge || true
        else
            /usr/bin/astrag remove || true
        fi
    fi
    if "$PURGE"; then
        rm -f /usr/bin/astrag /usr/bin/astra-clone
        rm -rf /opt/astrag /opt/astra-clone /etc/astrag /etc/astra-clone /var/lib/astrag /var/lib/astra-clone
        echo "==> AstraG has been completely removed."
    fi
    exit 0
fi

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

TMP_DIR=""
cleanup_tmp() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup_tmp EXIT

ensure_runtime_libs() {
    if ! ldconfig -p 2>/dev/null | grep -q "libssl.so.3" || ! ldconfig -p 2>/dev/null | grep -q "libz.so.1"; then
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libssl3 zlib1g ca-certificates || true
    fi
}

install_from_source() {
    local src_dir="$1"
    echo "==> Compiling native C binary astrag (astasy) from $src_dir/c_src..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc make libc6-dev libssl-dev zlib1g-dev binutils ca-certificates
    make -C "$src_dir/c_src" clean
    make -C "$src_dir/c_src" CC=gcc
    install -o root -g root -m 0755 "$src_dir/c_src/astrag" /usr/bin/astrag
}

ARCH="$(uname -m)"
INSTALLED_BIN=false

if ! "$FORCE_BUILD" && [ "$ARCH" = "x86_64" ]; then
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/astrag" ] && file "$SCRIPT_DIR/astrag" 2>/dev/null | grep -q "ELF"; then
        if ! "$SCRIPT_DIR/astrag" --version >/dev/null 2>&1; then
            ensure_runtime_libs
        fi
        if "$SCRIPT_DIR/astrag" --version >/dev/null 2>&1; then
            echo "==> Installing precompiled native C binary (/usr/bin/astrag)..."
            install -o root -g root -m 0755 "$SCRIPT_DIR/astrag" /usr/bin/astrag
            INSTALLED_BIN=true
        fi
    fi

    if ! "$INSTALLED_BIN" && [ -z "$SCRIPT_DIR" ]; then
        TMP_DIR="$(mktemp -d /tmp/astasy-inst.XXXXXX)"
        if ! command -v curl >/dev/null 2>&1; then
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates
        fi
        echo "==> Downloading static native C binary astrag from GitHub (udemika/astron)..."
        if curl -fsSL "$RAW_URL" -o "$TMP_DIR/astrag" && chmod 0755 "$TMP_DIR/astrag"; then
            if ! "$TMP_DIR/astrag" --version >/dev/null 2>&1; then
                ensure_runtime_libs
            fi
            if "$TMP_DIR/astrag" --version >/dev/null 2>&1; then
                install -o root -g root -m 0755 "$TMP_DIR/astrag" /usr/bin/astrag
                INSTALLED_BIN=true
            fi
        fi
    fi
fi

if ! "$INSTALLED_BIN"; then
    if [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/c_src" ]; then
        install_from_source "$SCRIPT_DIR"
    else
        TMP_DIR="$(mktemp -d /tmp/astasy-src.XXXXXX)"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git ca-certificates
        git clone --depth 1 "$REPO_URL" "$TMP_DIR/repo"
        if ! "$FORCE_BUILD" && [ "$ARCH" = "x86_64" ] && [ -f "$TMP_DIR/repo/astrag" ]; then
            chmod 0755 "$TMP_DIR/repo/astrag"
            if ! "$TMP_DIR/repo/astrag" --version >/dev/null 2>&1; then
                ensure_runtime_libs
            fi
            if "$TMP_DIR/repo/astrag" --version >/dev/null 2>&1; then
                install -o root -g root -m 0755 "$TMP_DIR/repo/astrag" /usr/bin/astrag
                INSTALLED_BIN=true
            fi
        fi
        if ! "$INSTALLED_BIN"; then
            install_from_source "$TMP_DIR/repo"
        fi
    fi
fi

# Clean up legacy Python files if upgrading from an older Python-based installation
rm -rf /opt/astrag /opt/astra-clone

if "$START"; then
    /usr/bin/astrag init "$CUSTOM_PORT" --start
else
    /usr/bin/astrag init "$CUSTOM_PORT" --no-start
fi
