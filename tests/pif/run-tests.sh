#!/usr/bin/env bash
# Host checks for the TrickyStore key-attestation port.
#
# The tests exercise the production sources directly (they are copied in by the
# script from the applied patch), with real ECDSA/RSA key material, so the
# attestation bytes and signature chains are actually verified rather than mocked.
#
# Requirements:
#   - a built `out/` tree or an AOSP checkout containing external/bouncycastle
#   - kxml2 (ships in prebuilts/misc/common/kxml2)
#
# Usage:  tests/pif/run-tests.sh /path/to/android/root
set -eu

ROOT="${1:-$(cd "$(dirname "$0")/../../../.." && pwd)}"
TOP="$ROOT"
BASE="$TOP/frameworks/base"
TESTS="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pif-tests.XXXXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
BC="$WORK/bc"
OUT="$WORK/classes"

if [ ! -d "$BASE/core/java/android/security/trickystore" ]; then
    echo "error: $BASE/core/java/android/security/trickystore not found." >&2
    echo "Apply patches/frameworks,base/0009-*.patch first." >&2
    exit 1
fi

KXML="$TOP/prebuilts/misc/common/kxml2/kxml2-2.3.0.jar"
if [ ! -f "$KXML" ]; then
    echo "error: $KXML not found." >&2
    exit 1
fi

mkdir -p "$BC" "$OUT/src"

echo "==> building the repackaged BouncyCastle used by the platform"
find "$TOP/external/bouncycastle/repackaged_platform/bcprov/src/main/java" \
     "$TOP/external/bouncycastle/repackaged_platform/bcpkix/src/main/java" \
     -name "*.java" > "$WORK/bc-sources.txt"
javac -nowarn -proc:none -d "$BC" @"$WORK/bc-sources.txt" || exit 1

echo "==> staging the production sources under test"
mkdir -p "$OUT/src/android/security/trickystore"
cp "$BASE"/core/java/android/security/trickystore/AttestationExtensionBuilder.java \
   "$BASE"/core/java/android/security/trickystore/AttestationLeafRewriter.java \
   "$BASE"/core/java/android/security/trickystore/BcCrypto.java \
   "$BASE"/core/java/android/security/trickystore/KeyBoxManager.java \
   "$BASE"/core/java/android/security/trickystore/LeafCertificateBuilder.java \
   "$BASE"/core/java/android/security/trickystore/TrickyStoreService.java \
   "$BASE"/core/java/android/security/trickystore/CertificateGenerator.java \
   "$BASE"/core/java/android/security/trickystore/KeyboxGenerationFallback.java \
   "$OUT/src/android/security/trickystore/"
# Host stubs: the real AttestationUtils reads Android system properties and boot
# images, and BcCrypto is package private so the checks need a bridge into it.
cp "$TESTS"/android/security/trickystore/*.java "$OUT/src/android/security/trickystore/"
cp -R "$TESTS/stubs/." "$OUT/src/"
mkdir -p "$OUT/src/android/util"
cp "$TESTS"/android/util/Log.java "$OUT/src/android/util/"
cp "$TESTS"/*.java "$OUT/src/"

# AIDL enum files contain plain integer constants usable by host javac.
for kind in Tag TagType Algorithm EcCurve ErrorCode KeyPurpose SecurityLevel; do
    dest="$OUT/src/android/hardware/security/keymint/$kind.java"
    {
        echo 'package android.hardware.security.keymint;'
        echo "public interface $kind {"
        sed -nE 's/^ +([A-Z][A-Z0-9_]*) = (.*),.*$/    int \1 = \2;/p' \
            "$TOP/hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/$kind.aidl"
        echo '}'
    } > "$dest"
done
mkdir -p "$OUT/src/android/system/keystore2"
{
    echo 'package android.system.keystore2; public interface Domain {'
    sed -nE 's/^ +([A-Z][A-Z0-9_]*) = (.*),.*$/ int \1 = \2;/p' "$TOP/system/hardware/interfaces/keystore2/aidl/android/system/keystore2/Domain.aidl"
    echo '}'
} > "$OUT/src/android/system/keystore2/Domain.java"

echo "==> compiling"
javac -nowarn -proc:none -cp "$BC:$KXML" -d "$OUT/classes" \
    $(find "$OUT/src" -name "*.java") || exit 1

echo "==> running"
CP="$OUT/classes:$BC:$KXML"
FAILED=0
TOTAL=0
for t in AttestationBuilderCheck KeyboxCheck HackerCheck SoftwareCheck DigestCheck ServiceCheck FallbackCheck; do
    STATUS=0
    RESULT=$(java -cp "$CP" "$t" 2>&1) || STATUS=$?
    N=$(printf '%s\n' "$RESULT" | grep -c '^ok:' || true)
    TOTAL=$((TOTAL + N))
    if [ "$STATUS" -ne 0 ]; then
        FAILED=1
        printf '%-24s FAILED\n' "$t"
        printf '%s\n' "$RESULT" | grep -E '^(FAIL|Exception)' | head -20 || true
    else
        printf '%-24s ok (%s checks)\n' "$t" "$N"
    fi
done

echo
if [ "$FAILED" -ne 0 ]; then
    echo "FAILED"
    exit 1
fi
echo "ALL PASSED ($TOTAL checks)"
