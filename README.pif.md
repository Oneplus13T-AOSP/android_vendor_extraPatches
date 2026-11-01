# Play Integrity keybox support on PixelOS 17

These patches add keybox-backed key attestation for the PIF path. Host tests
verify certificate construction and policy behaviour; they do not establish a
Play Integrity verdict on a device. A keybox alone does not guarantee any label.
See Google's [verdict documentation](https://developer.android.com/google/play/integrity/verdicts).

| Project | Patch |
| --- | --- |
| `frameworks/base` | `patches/frameworks,base/0009-key-attestation-trickystore.patch` |
| `frameworks/base` | `patches/frameworks,base/0010-limit-attestation-targets-and-refresh-patch-levels.patch` |
| `frameworks/base` | `patches/frameworks,base/0011-fix-certificate-generator-imports.patch` |
| `frameworks/base` | `patches/frameworks,base/0012-keystore-keybox-fallback-and-diagnostics.patch` |
| `frameworks/base` | `patches/frameworks,base/0013-remove-attestation-patch-level-overrides.patch` |
| `packages/apps/Settings` | `patches/packages,apps,Settings/0002-Settings-RKP-keybox-and-attestation-state.patch` |
| `packages/apps/Settings` | `patches/packages,apps,Settings/0003-remove-attestation-patch-level-preference.patch` |

`vendorsetup.sh` already applies every project's patches with `git am` in
filename order, so sourcing `build/envsetup.sh` is all that is needed. The
`0009-` through `0013-` / `0002-` through `0003-` numbering keeps each patch after the existing ones; `git am`
applies them in name order.

## Why the inherited code could not pass

The PIN/Play-Integrity hook that shipped (`chromium/…/PropImitationHooks`,
`KeyboxImitationHooks`, `KeyboxChainGenerator`) spoofs the *Build fields* of
`com.google.android.gms` and `com.android.vending`, but the attestation
certificate those processes receive still came from KeyMint with the handset's
real ODM identity. Three separate defects followed from that:

1. **Identity never rewritten.** GMS requests attestation with
   `ATTESTATION_ID_BRAND/DEVICE/PRODUCT/MANUFACTURER/MODEL` set to the handset's
   ODM values (`OnePlus` / `PHB110`). The certificate therefore asserted
   `OnePlus/PHB110` while the process Build asserted the spoofed Pixel profile.
   Basic integrity does not cross-check the two; device and strong do.
2. **Keybox parsing was too narrow.** The old loader flattened the XML into
   `EC.PRIV`, `EC.CERT_1`, … and the Settings importer required *both* an ECDSA
   and an RSA block. RKP keyboxes — the ones that reach a strong verdict —
   usually carry a single algorithm, so they were rejected before use.
3. **ECDSA signing could not work.** Android's repackaged BouncyCastle does not
   register an ECDSA JCA service (the platform uses Conscrypt), so
   `Signature.getInstance("SHA256withECDSA", "BC")` and
   `JcaContentSignerBuilder("SHA256withECDSA")` throw on device. Any re-signing
   path built on them fails silently into the "keep the hardware chain" branch.

## What the patches change

`frameworks/base`:

| File | Role |
| --- | --- |
| `core/java/android/security/trickystore/AttestationExtensionBuilder.java` | KeyMint `KeyDescription` encoder, ascending tag order as real KeyMint emits it. No Android dependencies. |
| `core/java/android/security/trickystore/AttestationLeafRewriter.java` | Re-signs a hardware leaf with the keybox key. Preserves tag 704 (`RootOfTrust`) byte for byte, rewrites 710/711/712/716/717 and 705/706/718/719, drops 713/714/715/723. |
| `core/java/android/security/trickystore/LeafCertificateBuilder.java` | Assembles and signs one leaf, verifying the result against the issuer. |
| `core/java/android/security/trickystore/BcCrypto.java` | X.509 sign/verify on the BC light API, bypassing the missing JCA service. The digest follows the algorithm name; the platform has no ECDSA JCA service, so a fixed SHA-256 would emit certificates whose OID and signature disagree. |
| `core/java/android/security/trickystore/CertificateGenerator.java` | Software attestation chain for a device whose TEE cannot attest at all. |
| `core/java/android/security/trickystore/KeyBoxManager.java` | RKP and legacy XML parsing, private-key/certificate match, issuer-signature chain validation, truncated reload protection. |
| `core/java/android/security/trickystore/TrickyStoreService.java` | Keybox and target list from `Settings.Secure`; caller resolution and per-package policy. |
| `core/java/android/security/trickystore/CertificateHacker.java` | Android adapter: resolves profile identity, boot values, patch levels. |
| `core/java/android/security/pif/PlayIntegrityProfile.java` | Read-only view of the PIF profile, same precedence and fingerprint derivation PIF uses. |
| `keystore/.../AndroidKeyStoreKeyPairGeneratorSpi.java` | Chooses software generation, hardware leaf re-signing, or no change; strips attestation tags from `importKey`. |
| `keystore/.../AndroidKeyStoreSpi.java` | Applies the chain rewrite on `engineGetCertificateChain`, and makes `engineGetCertificate` follow it. |
| `core/java/com/android/internal/util/PropImitationHooks.java` | Rebuilds the profile list per process instead of appending; maps `Build.VERSION` members; writes long/boolean fields correctly. |
| `keystore/.../KeyStore2.java`, `KeyStoreSecurityLevel.java` | Retain the backend security level and recover eligible TEE failures at the lower Java boundary, installing a real imported key and persisted certificate metadata. |
| `core/java/android/security/trickystore/KeyboxGenerationFallback.java` | Convert KeyMint request parameters, filter import tags, generate and persist the software chain, and clean up incomplete imports. |
| `services/.../AttestationService.java` | Warms the service and resolves the boot hash at boot. |
| `core/java/android/provider/Settings.java`, `packages/SettingsProvider/.../SecureSettingsValidators.java` | Declare and allow `tricky_store_target`. The manual patch-level override is removed by `0013`. |

`packages/apps/Settings`: accepts single-algorithm keyboxes, shows the actual
registration state read back from `Settings.Secure`, restarts GMS and Play Store
after a change. `0003` removes the confusing manual attestation patch-level entry and editor.

## Scope and safety

Attestation is rewritten **only** when all of these hold:

- the alias is not one of the internal probe aliases,
- the key has an attestation challenge,
- the key is a normal RSA/EC key (not StrongBox, not ML-DSA),
- the calling package is `com.google.android.gms` or `com.android.vending`,
- a keybox is configured.

With the default target list, other packages, including `android` and third-party
apps, keep their native attestation. Unattested Play Store keys also stay native.
Explicit `tricky_store_target` settings can opt other packages into rewriting.
The `0010` follow-up removes the broader inherited default target list.

`RootOfTrust` is taken from the hardware attestation when the TEE produced one,
so the verified-boot key and hash remain the genuine measured values. When the
TEE cannot attest, they come from `ro.boot.vbmeta.*`, then deterministically
from the active keybox certificate. Nothing is persisted: the attestation code
runs inside the requesting app process, which cannot write a system-private
directory, so a state file would silently fail there. A TEE probe runs once at
boot from `AttestationService`, where a nested KeyMint call is safe.

The keypair generator tries the hardware key first. Only when the TEE returns no
usable attestation does it delete that key and build a software chain, which
matches the verified ColorOS behaviour and avoids probing the TEE with a nested
key generation from inside another one.

Serial, IMEI, MEID and second IMEI are never signed, matching
`constructKeyImportArguments()`.

## Using it

1. Build and flash as usual.
2. Settings → System → Developer options → **Configure keybox XML**, pick the
   keybox. The summary switches to `Registered: N bytes, M certificate(s)`.
   An RKP keybox with only an ECDSA block is accepted.
3. GMS and Play Store restart automatically. Check Play Integrity with a raw
   `deviceRecognitionVerdict` read, not the summary UI.
Attestation patch levels follow `Build.VERSION.SECURITY_PATCH`, including any
PIF override already applied to that process. The developer option for manual
attestation dates has been removed; existing `tricky_store_patch` values are
ignored and no manual date input is required.

Removing the keybox restores the previous behaviour, where
`PropImitationHooks` blocks the DroidGuard certificate-chain request.

## Limits

- Passing the local chain checks does not establish that Google accepts the
  keybox or the ROM. Android 13+ device integrity requires hardware-backed proof
  of a locked bootloader and a certified manufacturer image; strong integrity
  additionally requires recent OS and vendor security updates. These are
  [server verdict requirements](https://developer.android.com/google/play/integrity/verdicts),
  not properties this patch or its host tests can guarantee.
- Keyboxes are user-supplied and are not part of this repository.
- `RootOfTrust` tag 704 is preserved, but a TEE that cannot attest at all leaves
  it based on `ro.boot.vbmeta.*` or a keybox-derived value. This is not a hardware measurement and does not establish a server verdict.
- The Play Store's own SDK spoofing (`spoofVendingSdk`) and the DroidGuard
  certificate-chain block are unchanged; this patch only adds the keybox-backed
  path and leaves the existing `PropImitationHooks` behaviour in place when no
  keybox is configured.

## Tests

`tests/pif/run-tests.sh <android-root>` builds the platform's repackaged
BouncyCastle, compiles the production classes from the applied patch, and runs
165 host checks with real ECDSA/RSA material:

- the extension encoder: tag set, ascending order, profile identity vs request
  identity, absent physical identifiers, RootOfTrust layout, RSA vs EC fields;
- keybox parsing: dual-algorithm and RKP single-algorithm documents, mismatched
  private key, unlinked chain, truncated document, reload preservation, and
  cross-algorithm leaf signing;
- hardware leaf re-signing: chain replacement, issuer verification, identity and
  patch rewrite, RootOfTrust preservation, stable re-signing, untouched
  behaviour without a profile;
- software chain generation: EC and RSA leaves, EC-only and RSA-only keyboxes;
- default policy scope, explicit policy overrides and software-fallback policy;
- actual Android `CertificateGenerator` and lower-boundary fallback with a host
  Keystore backend: request translation, one application-ID wrapper, persisted key
  IDs, private-key/leaf match, private-byte clearing and incomplete-import cleanup;
- signature digests: a SHA-384 signature verifies as SHA-384, not as SHA-256 or
  SHA-512, and is genuinely over the SHA-384 hash.

```
vendor/extraPatches/tests/pif/run-tests.sh /path/to/android/root
```

The reference diagnosis document is
`/home/ccc/바탕화면/codex/PIF-INTEGRITY-SOLUTION-20261030.ko.md`; the port follows
its "6-1 minimal port" order and its Evolution X `CertificateGenerator` /
`CertificateHacker` semantics.

## November 4 fallback diagnosis and follow-up

The device report records failed TEE requests and no observed software imports.
That does not, by itself, prove which Java hook or native caller was used. The
SPI-only implementation also skipped policy resolution when package lookup was
empty. `0012` fixes that concrete gap using the locally bound application name,
and adds recovery to `KeyStoreSecurityLevel.generateKey()` for callers that do
not use the SPI. It handles only TEE communication failure (-49) and missing
attestation keys (-74), with an active keybox and AUTO/GENERATE policy. StrongBox,
explicit attestation signers, internal probes and non-APP namespaces stay native.
A leaf-only (`?`) policy never replaces the key with a software import.

After building and flashing these patches, register a currently valid keybox and
run a fresh integrity request. Registration already restarts GMS and Play Store.
Capture the new logs without exposing keybox XML or request identifiers:

```sh
adb logcat -d -b all -s AndroidKeyStoreKeyPairGeneratorSpi:I KeyboxFallback:I TrickyStoreService:I '*:S'
```

`Keybox SPI entry` identifies the upper path. `KeyboxFallback` reports the actual
backend level, eligibility and policy; `Software fallback installed` means the
imported key and certificate metadata were read back successfully. If the lower
Java marker remains absent during a fresh -49 failure, native Binder use or a
runtime/build mismatch still needs investigation. Moving a Java hook cannot
intercept a caller that uses the native Binder API directly.

The report's keybox expires at 2026-11-04 10:54:52 UTC. These changes do not extend
certificate validity. The final patches passed the actual framework Turbine
header command, javac against the build classpath, 165 host checks, sequential
patch application and Settings XML parsing. They have not been flashed or shown
to produce all three Play Integrity labels on this device.
