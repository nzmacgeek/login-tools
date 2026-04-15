#!/usr/bin/env bash
#
# build-dpk.sh — Build a BlueyOS login-tools .dpk package
#
# Requirements: gcc, make, python3, tar, zstd
#
# Usage: ./build-dpk.sh [version]
#
set -euo pipefail

VERSION="${1:-1.0.0}"
ARCH="i386"
PKG_NAME="login-tools"
OUT_FILE="${PKG_NAME}-${VERSION}-${ARCH}.dpk"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Building binaries..."
make clean
make

echo "==> Setting permissions on setuid binaries..."
chmod u+s pkg/payload/usr/bin/passwd \
           pkg/payload/usr/bin/login  \
           pkg/payload/usr/bin/chsh

echo "==> Reading lifecycle scripts..."
POSTINST="$(cat pkg/meta/postinst)"
PRERM="$(cat pkg/meta/prerm)"

echo "==> Generating manifest.json..."
python3 - <<PYEOF
import json, os, hashlib, stat

payload_root = "pkg/payload"
files = []

for dirpath, dirnames, filenames in os.walk(payload_root):
    dirnames.sort()
    for fname in sorted(filenames):
        full = os.path.join(dirpath, fname)
        rel  = "/" + os.path.relpath(full, payload_root)
        st   = os.lstat(full)

        if stat.S_ISLNK(st.st_mode):
            target  = os.readlink(full)
            content = target.encode()
            fhash   = hashlib.sha256(content).hexdigest()
            files.append({
                "path":   rel,
                "type":   "symlink",
                "target": target,
                "hash":   fhash,
                "size":   len(content),
                "mode":   oct(stat.S_IMODE(st.st_mode)),
            })
        else:
            with open(full, "rb") as f:
                content = f.read()
            fhash = hashlib.sha256(content).hexdigest()
            files.append({
                "path": rel,
                "hash": fhash,
                "size": st.st_size,
                "mode": oct(stat.S_IMODE(st.st_mode)),
            })

with open("pkg/meta/postinst") as f:
    postinst = f.read()
with open("pkg/meta/prerm") as f:
    prerm = f.read()

manifest = {
    "name":        "${PKG_NAME}",
    "version":     "${VERSION}",
    "arch":        "${ARCH}",
    "description": "Login and password management tools for BlueyOS",
    "maintainer":  "BlueyOS Project",
    "homepage":    "https://github.com/nzmacgeek/blueyos",
    "depends":     [],
    "recommends":  [],
    "conflicts":   [],
    "provides":    ["passwd", "login", "useradd", "userdel", "usermod",
                    "groupadd", "groupdel", "groupmod", "chsh", "userlock",
                    "setup-root", "chmod", "chown", "chgrp"],
    "files":       files,
    "scripts": {
        "postinst": postinst,
        "prerm":    prerm,
    },
}

with open("pkg/meta/manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"  {len(files)} files catalogued.")
PYEOF

echo "==> Assembling .dpk archive..."
rm -f "$OUT_FILE"

# Try tar --zstd (needs zstd in PATH); fall back to pipe
if tar --zstd --version >/dev/null 2>&1 && command -v zstd >/dev/null 2>&1; then
    tar -C pkg --zstd -cf "$OUT_FILE" meta/ payload/
elif command -v zstd >/dev/null 2>&1; then
    tar -C pkg -cf - meta/ payload/ | zstd -o "$OUT_FILE"
else
    echo "ERROR: zstd is not installed. Install it with your package manager:"
    echo "  apt install zstd   # Debian/Ubuntu"
    echo "  pacman -S zstd     # Arch"
    exit 1
fi

echo ""
echo "==> Package ready: $OUT_FILE"
echo "    $(du -sh "$OUT_FILE" | cut -f1)  ${PKG_NAME} v${VERSION} (${ARCH})"
