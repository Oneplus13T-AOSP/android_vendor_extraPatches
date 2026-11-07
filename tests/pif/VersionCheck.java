import android.security.trickystore.AttestationUtils;
import android.security.trickystore.AttestationVersion;

/**
 * Checks the attestation version the ROM asserts and the zero-boot-value handling.
 *
 * <p>Verifiers cross-check the asserted KeyMint version against the attested key, so the
 * value has to describe the hardware, not the ROM. A PixelOS 17 build on KeyMint V3
 * hardware must not claim 500 just because the SDK is 37.
 *
 * <p>The mapping lives in {@link AttestationVersion} precisely so it can be checked here
 * with real numbers rather than asserted through a stub.
 */
public class VersionCheck {
    static int failures = 0;

    static void check(boolean condition, String name) {
        if (!condition) {
            failures++;
            System.out.println("FAIL: " + name);
        } else {
            System.out.println("ok:   " + name);
        }
    }

    public static void main(String[] args) {
        // API level -> KeyMint attestation version.
        int[][] cases = {
                {28, 400}, {29, 4}, {30, 4}, {31, 100}, {32, 100},
                {33, 200}, {34, 300}, {35, 300}, {36, 400}, {37, 500},
        };
        for (int[] c : cases) {
            int got = AttestationVersion.forApiLevel(c[0]);
            check(got == c[1], "API " + c[0] + " -> " + c[1] + " (got " + got + ")");
        }

        // This device: first_api_level=35 must yield KeyMint 3, not 400/500.
        check(AttestationVersion.forApiLevel(35) == 300,
                "OnePlus 13T (first API 35) asserts KeyMint 300");
        check(AttestationVersion.forApiLevel(37) != 300,
                "running SDK 37 alone would have asserted a different version");

        // Keymaster encoding keeps the 4 -> 41 quirk.
        check(AttestationVersion.keymasterVersion(4) == 41, "Keymaster 4 encodes as 41");
        check(AttestationVersion.keymasterVersion(300) == 300, "KeyMint 300 stays 300");
        check(AttestationVersion.keymasterVersion(500) == 500, "KeyMint 500 stays 500");

        // osVersion encoding: API 36 -> 160000, matching KeyMint.
        check(AttestationVersion.osVersion(35) == 350000, "osVersion API 35 = 350000");
        check(AttestationVersion.osVersion(36) == 360000, "osVersion API 36 = 360000");

        // Zero boot values must be treated as absent, not signed.
        check(AttestationUtils.isNullOrZeroBootKey(null), "null boot key is unusable");
        check(AttestationUtils.isNullOrZeroBootKey(new byte[32]), "zero boot key is unusable");
        byte[] key = new byte[32];
        key[31] = 1;
        check(!AttestationUtils.isNullOrZeroBootKey(key), "non-zero boot key is usable");
        check(AttestationUtils.isNullOrZeroBootHash(null), "null boot hash is unusable");
        check(AttestationUtils.isNullOrZeroBootHash(new byte[32]), "zero boot hash is unusable");
        check(!AttestationUtils.isNullOrZeroBootHash(key), "non-zero boot hash is usable");

        System.out.println();
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " FAILURE(S)");
        if (failures != 0) System.exit(1);
    }
}
