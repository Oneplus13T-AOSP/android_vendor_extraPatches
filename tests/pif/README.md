# PIF host checks

`run-tests.sh` compiles the production TrickyStore classes from the applied
`frameworks/base` patch against the platform's repackaged BouncyCastle and runs
the checks with generated ECDSA/RSA key material.

```
./run-tests.sh /path/to/android/root
```

`android/security/trickystore/AttestationUtils.java` is a stub for the host: the
real class reads Android system properties and boot images, which do not exist
outside the device. Everything the tests exercise (extension encoding, keybox
parsing, leaf re-signing, chain generation, service policy and fallback) is the production code.

Android context, settings and elapsed time are host stubs under `stubs/`, with a
controllable provider and clock for `ServiceCheck`. No test writes to the source
tree. Each run creates its own `pif-tests.XXXXXXXX` directory under `${TMPDIR:-/tmp}`
and removes it on exit. The Android root argument is optional when this repository
is checked out at `vendor/extraPatches`.

The host suite also compiles and runs the actual `CertificateGenerator` and
`KeyboxGenerationFallback` adapters. Android context, package lookup, settings,
profile, clock and Keystore operations use stubs under `stubs/`; key generation,
ASN.1 encoding, signing and certificate verification use the production code.
`FallbackCheck` checks eligibility, caller resolution, request translation,
application-ID encoding, persisted key metadata, private-key/certificate match,
cleanup after failures, and leaf-only policy. Enum constants are generated from
the checkout's KeyMint and Keystore AIDL sources, so a full Android source tree
including `hardware/interfaces` and `system/hardware/interfaces` is required.
Host success does not replace framework Turbine/javac compilation or device tests.
