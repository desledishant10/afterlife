#!/usr/bin/env bash
#
# Backup, restore, and verify the Afterlife license-signing private key.
#
# The private key at .secrets/afterlife_license_key.pem is the ONLY thing that
# can mint Pro licenses. It is not in git and cannot be regenerated: lose it and
# no new customer can ever be onboarded; rotating it invalidates every license
# already sold. See docs/KEY-MANAGEMENT.md for the full policy.
#
# This script NEVER sees your passphrase. The encryption tool prompts you
# directly on the terminal. Run it yourself, choose a strong passphrase, and
# store that passphrase somewhere separate from the encrypted file (a password
# manager). Anyone with both the blob and the passphrase has your minter.
#
# Usage:
#   scripts/key_backup.sh verify                     # key matches embedded pubkey?
#   scripts/key_backup.sh backup                     # encrypt -> .secrets/<key>.<ext>
#   scripts/key_backup.sh restore <blob> [dest]      # decrypt a backup
#
# Encryption tool is auto-selected: age (preferred), then gpg, then openssl.
# Set FORCE=1 to overwrite an existing output file.

set -euo pipefail

KEY="${AFTERLIFE_LICENSE_KEY:-.secrets/afterlife_license_key.pem}"
LICENSING="src/afterlife/licensing.py"

die() { echo "error: $*" >&2; exit 1; }

pick_tool() {
  if command -v age >/dev/null 2>&1; then echo age
  elif command -v gpg >/dev/null 2>&1; then echo gpg
  elif command -v openssl >/dev/null 2>&1; then echo openssl
  else die "need one of: age, gpg, openssl"; fi
}

ext_for() { case "$1" in age) echo age ;; gpg) echo gpg ;; openssl) echo enc ;; esac; }

encrypt() { # encrypt <tool> <in> <out>
  rm -f "$3"  # age/gpg refuse to overwrite; the caller has cleared the guard
  case "$1" in
    age)     age -p -o "$3" "$2" ;;
    gpg)     gpg --yes --symmetric --cipher-algo AES256 --output "$3" "$2" ;;
    openssl) openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -in "$2" -out "$3" ;;
  esac
}

decrypt() { # decrypt <tool> <in> <out>
  rm -f "$3"  # age/gpg refuse to overwrite an existing output file
  case "$1" in
    age)     age -d -o "$3" "$2" ;;
    gpg)     gpg --yes --decrypt --output "$3" "$2" ;;
    openssl) openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$2" -out "$3" ;;
  esac
}

decrypt_stdout() { # decrypt_stdout <tool> <in>  (plaintext to stdout, no temp file)
  case "$1" in
    age)     age -d "$2" ;;
    gpg)     gpg --quiet --decrypt "$2" ;;
    openssl) openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$2" ;;
  esac
}

cmd_verify() {
  [ -f "$KEY" ] || die "key not found: $KEY"
  command -v openssl >/dev/null 2>&1 || die "verify needs openssl"
  [ -f "$LICENSING" ] || die "cannot find $LICENSING (run from the repo root)"
  local derived embedded
  derived="$(openssl pkey -in "$KEY" -pubout 2>/dev/null)" ||
    die "cannot read a private key from $KEY"
  embedded="$(awk '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/' "$LICENSING")"
  if [ "$derived" = "$embedded" ]; then
    echo "OK: $KEY matches the embedded VENDOR_PUBLIC_KEY."
  else
    die "MISMATCH: $KEY does NOT match VENDOR_PUBLIC_KEY in $LICENSING.
Minting with this key would produce licenses that fail on customer installs."
  fi
}

cmd_backup() {
  [ -f "$KEY" ] || die "key not found: $KEY"
  local tool ext out
  tool="$(pick_tool)"
  ext="$(ext_for "$tool")"
  out="${KEY}.${ext}"
  if [ -e "$out" ] && [ "${FORCE:-}" != 1 ]; then
    die "$out already exists; set FORCE=1 to overwrite"
  fi

  # Clear any leftover round-trip temp files from an interrupted older run.
  rm -f "$(dirname "$KEY")"/.roundtrip.* 2>/dev/null || true

  echo "Encrypting $KEY with: $tool"
  echo "You will be prompted for a passphrase now, and once more to verify."
  echo "Pick a STRONG passphrase and keep it separate from the encrypted file."
  encrypt "$tool" "$KEY" "$out"
  chmod 600 "$out"

  # An untested backup is not a backup. Decrypt straight to a pipe and compare
  # byte-for-byte: the plaintext key is never written to a second file on disk.
  echo "Verifying the backup decrypts and matches the original..."
  cmp -s "$KEY" <(decrypt_stdout "$tool" "$out") ||
    die "round-trip FAILED; do not trust $out"

  echo
  echo "OK: wrote $out ($(wc -c <"$out" | tr -d ' ') bytes) and verified it round-trips."
  echo "Next:"
  echo "  1. Move $out OFFSITE (see docs/KEY-MANAGEMENT.md): a password-manager"
  echo "     secure note, an offline USB, and/or a cloud secrets store. Keep 2+ copies."
  echo "  2. Store the passphrase in your password manager, NOT next to the file."
  echo "  3. Once copies are safely offsite, you may delete the local $out."
}

cmd_restore() {
  local blob="${1:-}" dest="${2:-$KEY}"
  [ -n "$blob" ] || die "usage: $0 restore <encrypted-blob> [dest]"
  [ -f "$blob" ] || die "blob not found: $blob"
  if [ -e "$dest" ] && [ "${FORCE:-}" != 1 ]; then
    die "$dest already exists; set FORCE=1 to overwrite"
  fi
  local tool
  case "$blob" in
    *.age) tool=age ;;
    *.gpg) tool=gpg ;;
    *.enc) tool=openssl ;;
    *) die "unknown blob type: $blob (expected .age, .gpg, or .enc)" ;;
  esac
  command -v "$tool" >/dev/null 2>&1 || die "need $tool installed to restore $blob"

  mkdir -p "$(dirname "$dest")"
  chmod 700 "$(dirname "$dest")" 2>/dev/null || true
  echo "Decrypting $blob with $tool (you will be prompted for the passphrase)..."
  decrypt "$tool" "$blob" "$dest"
  chmod 600 "$dest"
  echo "Restored $dest. Verifying against the embedded public key..."
  cmd_verify
}

case "${1:-}" in
  backup)  cmd_backup ;;
  restore) shift; cmd_restore "$@" ;;
  verify)  cmd_verify ;;
  *)
    echo "usage: $0 {verify | backup | restore <blob> [dest]}" >&2
    exit 2
    ;;
esac
