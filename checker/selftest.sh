#!/usr/bin/env bash
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$ROOT"
GO="${GO:-go}"
CHECK="${CHECK:-$ROOT/checker/check.sh}"
OSSL_DEFAULT="${OSSL:-$(command -v openssl || true)}"
export GOTOOLCHAIN=local
export GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false"
export TIMEOUT="${TIMEOUT:-8}"
OUT="${1:?usage: selftest.sh <out-dir>}"
[ -e "$OUT" ] && { echo "refusing: $OUT exists" >&2; exit 2; }
mkdir -p "$OUT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ok=0 bad=0

printf 'control\texpected\tclass\ttimeout_rows\tcheck_seconds\tjson\tsummary\n' > "$OUT/summary.tsv"

run_check() {
  local rec="$1"; shift
  local t0; t0=$(date +%s.%N)
  timeout 1800 env OSSL="$OSSL_DEFAULT" "$@" bash "$CHECK" --json "$rec/check.json" > "$rec/check.raw" 2>&1
  echo $? > "$rec/check.rc"
  if [ ! -f "$rec/check.json" ]; then echo absent
  elif python3 -m json.tool "$rec/check.json" > /dev/null 2>&1; then echo valid
  else echo invalid; fi > "$rec/json.state"
  awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f\n", b-a}' > "$rec/check.seconds"
  sed 's/\x1b\[[0-9;]*m//g' "$rec/check.raw" > "$rec/check.txt"
}

count() { grep -cE "$1" "$2" 2>/dev/null || true; }

classify() {
  local kind="$1" rec="$2" s f e d to
  s=$(grep '^SUMMARY' "$rec/check.txt" | tail -1)
  if [ -z "$s" ]; then
    [ "$(cat "$rec/check.rc")" = 124 ] && echo CHECKER_TIMEOUT || echo NO_SUMMARY; return
  fi
  f=$(echo "$s" | sed -n 's/.*fail=\([0-9]*\).*/\1/p')
  e=$(echo "$s" | sed -n 's/.*error=\([0-9]*\).*/\1/p')
  d=$(echo "$s" | sed -n 's/.*depmiss=\([0-9]*\).*/\1/p')
  to=$(count '^  ERROR .*timed out after' "$rec/check.txt")
  case "$kind" in
    fail)
      if [ "$f" -gt 0 ]; then echo CAUGHT
      elif [ "$to" -gt 0 ]; then echo MISSED_TIMEOUT_INSTEAD_OF_FAIL
      elif [ "$e" -gt 0 ]; then echo MISSED_ERROR_INSTEAD_OF_FAIL
      elif [ "$d" -gt 0 ]; then echo MISSED_DEPMISS
      else echo MISSED_UNDETECTED; fi ;;
    error)
      if [ "$e" -gt 0 ]; then echo CAUGHT
      elif [ "$f" -gt 0 ]; then echo MISSED_FAIL_INSTEAD_OF_ERROR
      elif [ "$d" -gt 0 ]; then echo MISSED_DEPMISS
      else echo MISSED_UNDETECTED; fi ;;
    depmiss)
      if [ "$d" -gt 0 ] && [ "$f" -eq 0 ]; then echo CAUGHT
      else echo MISSED_UNDETECTED; fi ;;
    row:*)
      local want="${kind#row:}" got
      got=$(awk -v c="${want%%=*}" '$2 == c {print $1}' "$rec/check.txt" | head -1)
      if [ "$got" = "${want#*=}" ]; then echo CAUGHT; else echo "MISSED_ROW_${got:-ABSENT}"; fi ;;
    clean)
      if [ "$f" -eq 0 ] && [ "$d" -eq 0 ] && [ "$e" -eq 0 ]; then echo CLEAN
      elif [ "$to" -gt 0 ]; then echo DIRTY_TIMEOUT
      elif [ "$e" -gt 0 ]; then echo DIRTY_ERROR
      elif [ "$d" -gt 0 ]; then echo DIRTY_DEPMISS
      else echo DIRTY_FAIL; fi ;;
  esac
}

finish() {
  local name="$1" kind="$2" class="$3" rec="$4" color=32 s to secs js
  js=$(cat "$rec/json.state" 2>/dev/null || echo not-run)
  case "$class" in CAUGHT|CLEAN) [ "$js" = valid ] || class="$class+JSON_${js^^}" ;; esac
  case "$class" in CAUGHT|CLEAN) ok=$((ok+1)) ;; *) bad=$((bad+1)); color=31 ;; esac
  s=$(grep '^SUMMARY' "$rec/check.txt" 2>/dev/null | tail -1)
  to=$(count '^  ERROR .*timed out after' "$rec/check.txt"); to=${to:-0}
  secs=$(cat "$rec/check.seconds" 2>/dev/null || echo -)
  printf '  \033[%sm%-34s\033[0m %-38s expected %-7s timeout_rows=%-3s check_s=%-6s json=%-7s [%s]\n' \
    "$color" "$class" "$name" "$kind" "$to" "$secs" "$js" "$s"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$kind" "$class" "$to" "$secs" "$js" "$s" >> "$OUT/summary.tsv"
}

expect_catch() {
  local name="$1" kind="$2" patch="$3"
  local dir="$WORK/$name" rec="$OUT/$name"
  mkdir -p "$rec" 2>&1
  mkdir -p "$dir"
  cp "$SRC/go.mod" "$SRC/go.sum" "$dir/"
  cp -r "$SRC/cmd" "$dir/"
  python3 - "$dir/cmd/mldsa-signer/main.go" "$patch" > "$rec/patch.log" 2>&1 <<'PY'
import sys, pathlib
path, patch = sys.argv[1], sys.argv[2]
src = pathlib.Path(path).read_text()
for hunk in patch.split('###'):
    if not hunk.strip():
        continue
    old, new = hunk.split('||>')
    if old not in src:
        sys.exit("PATCH DID NOT APPLY: " + old[:60])
    src = src.replace(old, new, 1)
pathlib.Path(path).write_text(src)
PY
  if [ $? -ne 0 ]; then finish "$name" "$kind" PATCH_FAILED "$rec"; return; fi
  diff -u "$SRC/cmd/mldsa-signer/main.go" "$dir/cmd/mldsa-signer/main.go" > "$rec/patch.diff"

  mkdir -p "$dir/bin"
  cp "$ROOT/bin/filesigner-rsa" "$dir/bin/"
  local target="$dir/bin/filesigner-mldsa"
  local t0; t0=$(date +%s.%N)
  (cd "$dir" && "$GO" build -o "$target" ./cmd/mldsa-signer) > "$rec/build.log" 2>&1
  local brc=$?
  awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f\n", b-a}' > "$rec/build.seconds"
  if [ "$brc" -ne 0 ]; then finish "$name" "$kind" BUILD_FAILED "$rec"; return; fi

  run_check "$rec" BIN="$dir/bin" CAND_BIN="$dir/bin/candidate"
  finish "$name" "$kind" "$(classify "$kind" "$rec")" "$rec"
}

echo "=== checker self-test: deliberately faulty controls ==="
echo "each mutant below MUST be caught, in the right category"
echo

expect_catch "empty-context" fail \
  'const SigContext = "filesigner/v1"||>const SigContext = ""'

expect_catch "prehash-instead-of-pure" fail \
  '"crypto/rand"||>"crypto/rand"
	"crypto/sha256"###if err := mldsa44.SignTo(sk, msg, []byte(SigContext), randomizedSigning, sig); err != nil {||>d := sha256.Sum256(msg)
	if err := mldsa44.SignTo(sk, d[:], []byte(SigContext), randomizedSigning, sig); err != nil {'

expect_catch "verify-accepts-everything" fail \
  'if !mldsa44.Verify(pk, msg, []byte(SigContext), sig) {
		return fail(exitReject, "signature verification failed")
	}||>if !mldsa44.Verify(pk, msg, []byte(SigContext), sig) {
		_ = pk // deliberate fault: notice the failure, then accept anyway
	}'

expect_catch "malformed-reported-as-reject" fail \
  'return fail(exitMalformed, "signature is %d bytes, expected %d",||>return fail(exitReject, "signature is %d bytes, expected %d",'

expect_catch "raw-public-key-not-spki" fail \
  'return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{Algorithm: oidMLDSA44},
		PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})||>return raw, nil // deliberate fault: raw bytes instead of SPKI'

expect_catch "panic-on-verify" error \
  'sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fail(exitIO, "reading %s: %w", sigPath, err)
	}
	if len(sig) != mldsa44.SignatureSize {||>panic("deliberate fault: crash during verify")
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fail(exitIO, "reading %s: %w", sigPath, err)
	}
	if len(sig) != mldsa44.SignatureSize {'

expect_catch "hang-on-verify" error \
  '"os"||>"os"
	"time"###func verify(pubPath, inPath, sigPath string) error {||>func verify(pubPath, inPath, sigPath string) error {
	time.Sleep(10 * time.Minute)'

expect_catch "deterministic-signing" fail \
  'const randomizedSigning = true||>const randomizedSigning = false'

expect_catch "signature-byte-100-is-0x01" clean \
  'if err := mldsa44.SignTo(sk, msg, []byte(SigContext), randomizedSigning, sig); err != nil {
		return fail(exitIO, "signing: %w", err)
	}||>for {
		if err := mldsa44.SignTo(sk, msg, []byte(SigContext), randomizedSigning, sig); err != nil {
			return fail(exitIO, "signing: %w", err)
		}
		if sig[100] == 0x01 {
			break
		}
	}'

expect_catch "hang-on-keygen" error \
  '"os"||>"os"
	"time"###func keygen(privPath, pubPath string) error {||>func keygen(privPath, pubPath string) error {
	time.Sleep(10 * time.Minute)'

expect_catch "sign-writes-nothing" "row:signing-is-randomized=FAIL" \
  'if err := os.WriteFile(sigPath, sig, 0o644); err != nil {||>if err := error(nil); err != nil { // deliberate fault: nothing is written'

expect_catch "reject-message-mentions-runtime-error" clean \
  'return fail(exitReject, "signature verification failed")||>return fail(exitReject, "signature verification failed (no runtime error: the signature is invalid)")'

expect_catch "failure-detail-with-json-hostile-text" fail \
  'return fail(exitMalformed, "signature is %d bytes, expected %d",||>return fail(exitReject, "signature is \"%d\" bytes,	C:\\sig, expected %d",'

expect_catch "mismatched-embedded-public-key" fail \
  'pkDER, err := marshalPublic(pk)||>seed[0] ^= 0x01
	pk, _ = mldsa44.NewKeyFromSeed(&seed)
	pkDER, err := marshalPublic(pk)'

echo
rec="$OUT/missing-openssl"; mkdir -p "$rec" 2>&1
run_check "$rec" OSSL="$WORK/no-such-openssl" BIN="$ROOT/bin"
finish missing-openssl depmiss "$(classify depmiss "$rec")" "$rec"

echo
rec="$OUT/unmodified-application"; mkdir -p "$rec" 2>&1
run_check "$rec" BIN="$ROOT/bin"
finish unmodified-application clean "$(classify clean "$rec")" "$rec"

echo
echo "SELFTEST caught=$ok missed=$bad"
echo "(counted as in the original: every class other than CAUGHT/CLEAN is 'missed'; see $OUT/summary.tsv)"
echo "caught=$ok missed=$bad" > "$OUT/result.txt"
[ "$bad" -eq 0 ] || exit 1
exit 0
