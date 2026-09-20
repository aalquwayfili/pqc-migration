#!/usr/bin/env bash
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="${BIN:-$ROOT/bin}"
OSSL="${OSSL:-$(command -v openssl || true)}"
CTX="filesigner/v1"
TIMEOUT="${TIMEOUT:-30}"

JSON_OUT=""
[ "${1:-}" = "--json" ] && JSON_OUT="${2:-}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0 fail=0 depmiss=0 error=0
: > "$WORK/rows.tsv"

record() {
  local name="$1" status="$2" detail="$3"
  case "$status" in
    PASS)    pass=$((pass+1));    printf '  \033[32mPASS\033[0m    %-46s %s\n' "$name" "$detail" ;;
    FAIL)    fail=$((fail+1));    printf '  \033[31mFAIL\033[0m    %-46s %s\n' "$name" "$detail" ;;
    DEPMISS) depmiss=$((depmiss+1)); printf '  \033[33mDEPMISS\033[0m %-46s %s\n' "$name" "$detail" ;;
    ERROR)   error=$((error+1));   printf '  \033[35mERROR\033[0m   %-46s %s\n' "$name" "$detail" ;;
  esac
  printf '%s\t%s\t%s\n' "$name" "$status" "$(printf '%s' "$detail" | tr '\t\n\r' '   ')" >> "$WORK/rows.tsv"
}

run_rc() {
  timeout "$TIMEOUT" "$@" >"$WORK/out" 2>"$WORK/err"
  echo $?
}

# Go panics use exit 2, which is also the contract's usage-error code.
crashed() {
  grep -qE '^panic: |^fatal error: |^goroutine [0-9]+ \[' "$WORK/err" 2>/dev/null
}

expect_rc() {
  local name="$1" want="$2" got="$3"
  if [ "$got" -eq 124 ]; then
    record "$name" ERROR "timed out after ${TIMEOUT}s"
  elif [ "$got" -ge 128 ]; then
    record "$name" ERROR "killed by signal $((got-128))"
  elif crashed; then
    record "$name" ERROR "runtime crash (exit $got): $(grep -m1 -E '^panic:|^fatal error:' "$WORK/err" | head -c 120)"
  elif [ "$got" -eq "$want" ]; then
    record "$name" PASS "exit $got"
  else
    record "$name" FAIL "expected exit $want, got $got: $(head -c 160 "$WORK/err" | tr '\n' ' ')"
  fi
}

echo "=== filesigner external checker ==="
echo "root:    $ROOT"

echo
echo "-- preflight --"
if [ ! -x "$OSSL" ]; then
  record "openssl-present" DEPMISS "no openssl at $OSSL (set OSSL to an OpenSSL 3.5.8 executable)"
else
  OSSL_VER="$("$OSSL" version 2>/dev/null | awk '{print $2}')"
  record "openssl-present" PASS "OpenSSL $OSSL_VER"
  if "$OSSL" list -signature-algorithms 2>/dev/null | grep -q 'ML-DSA-44'; then
    record "openssl-has-mldsa44" PASS "ML-DSA-44 available"
  else
    record "openssl-has-mldsa44" DEPMISS "this OpenSSL has no ML-DSA-44 (needs >= 3.5)"
  fi
fi
for b in filesigner-mldsa filesigner-rsa; do
  if [ -x "$BIN/$b" ]; then record "binary-$b" PASS "present"
  else record "binary-$b" DEPMISS "not built: $BIN/$b"; fi
done

if [ "$depmiss" -gt 0 ]; then
  echo
  echo "prerequisites missing; no cryptographic checks were run."
  echo "SUMMARY pass=$pass fail=$fail depmiss=$depmiss error=$error"
  [ -n "$JSON_OUT" ] && python3 -c 'import json, sys; json.dump({"totals": dict(zip(("pass", "fail", "depmiss", "error"), map(int, sys.argv[2:]))), "checks": [dict(zip(("check", "status", "detail"), l.rstrip("\n").split("\t", 2))) for l in open(sys.argv[1]) if l.strip()]}, open(sys.argv[6], "w"), indent=2)' "$WORK/rows.tsv" "$pass" "$fail" "$depmiss" "$error" "$JSON_OUT"
  exit 3
fi

APP="$BIN/filesigner-mldsa"
if [ -z "${MSG_SEED:-}" ]; then
  printf 'the quick brown fox jumps over the lazy dog\n' > "$WORK/msg.bin"
  printf 'the quick brown fox jumps over the lazy dov\n' > "$WORK/msg_tampered.bin"
  echo "100 0" > "$WORK/flip"
else
  python3 - "$WORK" "$MSG_SEED" <<'GEN'
import random, sys
work, r = sys.argv[1], random.Random(int(sys.argv[2]))
msg = r.randbytes(r.randint(1, 4096))
bad = bytearray(msg); i = r.randrange(len(msg)); bad[i] ^= 1 << r.randrange(8)
open(f"{work}/msg.bin", "wb").write(msg)
open(f"{work}/msg_tampered.bin", "wb").write(bad)
open(f"{work}/flip", "w").write(f"{r.randrange(2336)} {r.randrange(8)}")
print(f"fresh inputs: seed={sys.argv[2]} msg_len={len(msg)} tamper_byte={i}")
GEN
fi

echo
echo "-- application entry points --"
expect_rc "app-keygen" 0 "$(run_rc "$APP" keygen -priv "$WORK/app.key" -pub "$WORK/app.pub")"
expect_rc "app-sign"   0 "$(run_rc "$APP" sign -priv "$WORK/app.key" -in "$WORK/msg.bin" -sig "$WORK/app.sig")"
expect_rc "app-verify-own-signature" 0 \
  "$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg.bin" -sig "$WORK/app.sig")"

if [ -f "$WORK/app.sig" ]; then
  n=$(wc -c < "$WORK/app.sig")
  [ "$n" -eq 2420 ] && record "signature-size" PASS "2420 bytes" \
                    || record "signature-size" FAIL "expected 2420, got $n"
fi

echo
echo "-- key format interoperability --"
rc=$(run_rc "$OSSL" pkey -in "$WORK/app.key" -noout)
expect_rc "openssl-reads-app-private-key" 0 "$rc"
rc=$(run_rc "$OSSL" pkey -pubin -in "$WORK/app.pub" -noout)
expect_rc "openssl-reads-app-public-key" 0 "$rc"

alg=$("$OSSL" pkey -pubin -in "$WORK/app.pub" -noout -text 2>/dev/null | head -1)
case "$alg" in
  *ML-DSA-44*) record "app-public-key-is-mldsa44" PASS "$alg" ;;
  *)           record "app-public-key-is-mldsa44" FAIL "reported: ${alg:-<none>}" ;;
esac

echo
echo "-- demonstration 1: app signature verifies under OpenSSL --"
rc=$(run_rc "$OSSL" pkeyutl -verify -pubin -inkey "$WORK/app.pub" -rawin \
       -in "$WORK/msg.bin" -pkeyopt "context-string:$CTX" -sigfile "$WORK/app.sig")
expect_rc "openssl-verifies-app-signature" 0 "$rc"

echo
echo "-- demonstration 2: OpenSSL signature verifies through the app --"
rc=$(run_rc "$OSSL" pkeyutl -sign -inkey "$WORK/app.key" -rawin -in "$WORK/msg.bin" \
       -pkeyopt "context-string:$CTX" -out "$WORK/ossl.sig")
expect_rc "openssl-signs-with-app-key" 0 "$rc"
rc=$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg.bin" -sig "$WORK/ossl.sig")
expect_rc "app-verifies-openssl-signature" 0 "$rc"

rc=$(run_rc "$OSSL" genpkey -algorithm ML-DSA-44 -out "$WORK/ossl.key")
expect_rc "openssl-generates-key" 0 "$rc"
timeout "$TIMEOUT" "$OSSL" pkey -in "$WORK/ossl.key" -pubout -out "$WORK/ossl.pub" 2>/dev/null
rc=$(run_rc "$OSSL" pkeyutl -sign -inkey "$WORK/ossl.key" -rawin -in "$WORK/msg.bin" \
       -pkeyopt "context-string:$CTX" -out "$WORK/ossl_own.sig")
expect_rc "openssl-signs-with-own-key" 0 "$rc"
rc=$(run_rc "$APP" verify -pub "$WORK/ossl.pub" -in "$WORK/msg.bin" -sig "$WORK/ossl_own.sig")
expect_rc "app-verifies-foreign-key-signature" 0 "$rc"
rc=$(run_rc "$APP" sign -priv "$WORK/ossl.key" -in "$WORK/msg.bin" -sig "$WORK/app_foreign.sig")
expect_rc "app-signs-with-openssl-key" 0 "$rc"
rc=$(run_rc "$OSSL" pkeyutl -verify -pubin -inkey "$WORK/ossl.pub" -rawin \
       -in "$WORK/msg.bin" -pkeyopt "context-string:$CTX" -sigfile "$WORK/app_foreign.sig")
expect_rc "openssl-verifies-that-roundtrip" 0 "$rc"

echo
echo "-- demonstration 3: required rejections (exit 1 = rejected, 3 = malformed) --"

rc=$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg_tampered.bin" -sig "$WORK/app.sig")
expect_rc "reject-tampered-message" 1 "$rc"

rc=$(run_rc "$APP" keygen -priv "$WORK/other.key" -pub "$WORK/other.pub")
expect_rc "app-keygen-second-key-pair" 0 "$rc"
rc=$(run_rc "$APP" verify -pub "$WORK/other.pub" -in "$WORK/msg.bin" -sig "$WORK/app.sig")
expect_rc "reject-wrong-key" 1 "$rc"

rc=$(run_rc "$OSSL" pkeyutl -sign -inkey "$WORK/app.key" -rawin -in "$WORK/msg.bin" \
       -pkeyopt "context-string:wrong-context" -out "$WORK/wrongctx.sig")
expect_rc "openssl-signs-wrong-context" 0 "$rc"
rc=$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg.bin" -sig "$WORK/wrongctx.sig")
expect_rc "reject-wrong-context" 1 "$rc"

rc=$(run_rc "$OSSL" pkeyutl -sign -inkey "$WORK/app.key" -rawin -in "$WORK/msg.bin" \
       -out "$WORK/noctx.sig")
expect_rc "openssl-signs-empty-context" 0 "$rc"
rc=$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg.bin" -sig "$WORK/noctx.sig")
expect_rc "reject-empty-context" 1 "$rc"

cp "$WORK/app.sig" "$WORK/bitflip.sig"
python3 -c 'import sys; o, b = map(int, open(sys.argv[2]).read().split())
s = bytearray(open(sys.argv[1], "rb").read()); s[o] ^= 1 << b; open(sys.argv[1], "wb").write(s)' \
  "$WORK/bitflip.sig" "$WORK/flip" 2>/dev/null
rc=$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg.bin" -sig "$WORK/bitflip.sig")
expect_rc "reject-flipped-bit" 1 "$rc"

head -c 100 "$WORK/app.sig" > "$WORK/short.sig"
rc=$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg.bin" -sig "$WORK/short.sig")
expect_rc "malformed-truncated-signature" 3 "$rc"
cat "$WORK/app.sig" "$WORK/app.sig" > "$WORK/long.sig"
rc=$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg.bin" -sig "$WORK/long.sig")
expect_rc "malformed-overlong-signature" 3 "$rc"
printf 'not a key at all\n' > "$WORK/garbage.pub"
rc=$(run_rc "$APP" verify -pub "$WORK/garbage.pub" -in "$WORK/msg.bin" -sig "$WORK/app.sig")
expect_rc "malformed-garbage-public-key" 3 "$rc"

rc=$(run_rc "$BIN/filesigner-rsa" keygen -priv "$WORK/rsa.key" -pub "$WORK/rsa.pub")
expect_rc "rsa-keygen-for-wrong-algorithm-test" 0 "$rc"
rc=$(run_rc "$APP" verify -pub "$WORK/rsa.pub" -in "$WORK/msg.bin" -sig "$WORK/app.sig")
expect_rc "malformed-wrong-algorithm-key" 3 "$rc"

echo
echo "-- demonstration 4: key persistence --"
cp "$WORK/app.key" "$WORK/reload.key"; cp "$WORK/app.pub" "$WORK/reload.pub"
rc=$(run_rc "$APP" sign -priv "$WORK/reload.key" -in "$WORK/msg.bin" -sig "$WORK/reload.sig")
expect_rc "sign-with-reloaded-key" 0 "$rc"
rc=$(run_rc "$APP" verify -pub "$WORK/reload.pub" -in "$WORK/msg.bin" -sig "$WORK/reload.sig")
expect_rc "verify-with-reloaded-key" 0 "$rc"
rc=$(run_rc "$OSSL" pkeyutl -verify -pubin -inkey "$WORK/reload.pub" -rawin \
       -in "$WORK/msg.bin" -pkeyopt "context-string:$CTX" -sigfile "$WORK/reload.sig")
expect_rc "openssl-verifies-reloaded-key-signature" 0 "$rc"

to_der() { timeout "$TIMEOUT" "$OSSL" pkey -pubin -in "$1" -pubout -outform DER -out "$2" 2>/dev/null; }
timeout "$TIMEOUT" "$OSSL" pkey -in "$WORK/app.key" -pubout -out "$WORK/derived.pub" 2>/dev/null
if to_der "$WORK/derived.pub" "$WORK/derived.pub.der" && to_der "$WORK/app.pub" "$WORK/app.pub.der"; then
  if cmp -s "$WORK/derived.pub.der" "$WORK/app.pub.der"; then
    record "private-key-carries-matching-public-key" PASS "identical SPKI DER"
  else
    record "private-key-carries-matching-public-key" FAIL "derived public key differs"
  fi
else
  record "private-key-carries-matching-public-key" FAIL "could not decode a public key to DER"
fi

sed 's/$/\r/' "$WORK/app.pub" > "$WORK/app_crlf.pub"
rc=$(run_rc "$APP" verify -pub "$WORK/app_crlf.pub" -in "$WORK/msg.bin" -sig "$WORK/app.sig")
expect_rc "app-accepts-crlf-public-key" 0 "$rc"

echo
echo "-- demonstration 5: signing is randomized, so tests must verify not compare --"
rc=$(run_rc "$APP" sign -priv "$WORK/app.key" -in "$WORK/msg.bin" -sig "$WORK/app2.sig")
expect_rc "app-sign-second-signature" 0 "$rc"
sz() { [ -f "$1" ] && wc -c < "$1" || echo 0; }
if [ "$(sz "$WORK/app.sig")" -ne 2420 ] || [ "$(sz "$WORK/app2.sig")" -ne 2420 ]; then
  record "signing-is-randomized" FAIL "need two 2420-byte signatures, got $(sz "$WORK/app.sig") and $(sz "$WORK/app2.sig") bytes"
elif cmp -s "$WORK/app.sig" "$WORK/app2.sig"; then
  record "signing-is-randomized" FAIL "two signatures were byte-identical"
else
  record "signing-is-randomized" PASS "two signatures differ, both verify"
fi
rc=$(run_rc "$APP" verify -pub "$WORK/app.pub" -in "$WORK/msg.bin" -sig "$WORK/app2.sig")
expect_rc "second-signature-also-verifies" 0 "$rc"

echo
echo "SUMMARY pass=$pass fail=$fail depmiss=$depmiss error=$error"

if [ -n "$JSON_OUT" ]; then
  python3 - "$WORK/rows.tsv" "$JSON_OUT" "$("$OSSL" version 2>/dev/null)" "$CTX" "${MSG_SEED:-}" <<'JSON'
import json, sys
rows, out, openssl, ctx, seed = sys.argv[1:6]
checks = [dict(zip(("check", "status", "detail"), l.rstrip("\n").split("\t", 2)))
          for l in open(rows, encoding="utf-8", errors="replace") if l.strip()]
totals = {k: sum(c["status"] == k.upper() for c in checks) for k in ("pass", "fail", "depmiss", "error")}
doc = {"openssl": openssl, "context": ctx, "msg_seed": int(seed) if seed else None,
       "totals": totals, "checks": checks}
json.dump(doc, open(out, "w"), indent=2)
JSON
  echo "wrote $JSON_OUT"
fi

[ "$error"   -gt 0 ] && exit 4
[ "$depmiss" -gt 0 ] && exit 3
[ "$fail"    -gt 0 ] && exit 1
exit 0
