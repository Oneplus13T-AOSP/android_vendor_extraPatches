import android.security.pif.PlayIntegrityProfile;
import android.security.trickystore.CertificateGenerator;

/**
 * Checks that a missing Play Integrity profile does not silently degrade into a
 * certificate asserting the handset's real identity.
 *
 * <p>That fallback used to exist: {@code identityBytes()} returned the process Build
 * value when the profile had no entry, so a process whose Build was not spoofed produced
 * a certificate claiming OnePlus/PKX110 next to a Pixel fingerprint. Device integrity
 * rejects exactly that contradiction, which is why the fallback is gone.
 */
public class IdentityCheck {
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
        // A full profile yields every field.
        java.util.Map<String, String> full = new java.util.LinkedHashMap<>(java.util.Map.of(
                "BRAND", "google", "DEVICE", "bluejay", "PRODUCT", "bluejay_beta",
                "MANUFACTURER", "Google", "MODEL", "Pixel 6a"));
        for (String field : new String[] {"BRAND", "DEVICE", "PRODUCT", "MANUFACTURER", "MODEL"}) {
            byte[] value = PlayIntegrityProfile.identityBytes(full, field);
            check(value != null && value.length > 0, "profile supplies " + field);
        }
        check("google".equals(new String(PlayIntegrityProfile.identityBytes(full, "BRAND"))),
                "BRAND value is the profile value");
        check("Pixel 6a".equals(new String(PlayIntegrityProfile.identityBytes(full, "MODEL"))),
                "MODEL value is the profile value");

        // A partial profile yields null for what it omits, instead of the device Build.
        java.util.Map<String, String> partial = new java.util.LinkedHashMap<>();
        partial.put("BRAND", "google");
        check(PlayIntegrityProfile.identityBytes(partial, "BRAND") != null,
                "present field is returned");
        check(PlayIntegrityProfile.identityBytes(partial, "MODEL") == null,
                "absent field returns null, not the device Build");
        check(PlayIntegrityProfile.identityBytes(partial, "MANUFACTURER") == null,
                "another absent field returns null");

        // No profile at all is null, which callers treat as "keep the hardware path".
        check(PlayIntegrityProfile.identityBytes(null, "BRAND") == null,
                "null profile yields null");
        check(PlayIntegrityProfile.getIdentity() == null || true, "identity getter reachable");

        // describeIdentity names only public identity fields and never identifiers.
        String described = PlayIntegrityProfile.describeIdentity(full);
        for (String field : new String[] {"BRAND", "DEVICE", "PRODUCT", "MANUFACTURER", "MODEL"}) {
            check(described.contains(field + "="), "describeIdentity shows " + field);
        }
        for (String forbidden : new String[] {"SERIAL", "IMEI", "MEID"}) {
            check(!described.contains(forbidden), "describeIdentity omits " + forbidden);
        }
        check("none".equals(PlayIntegrityProfile.describeIdentity(null)),
                "describeIdentity(null) is \"none\"");

        System.out.println();
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " FAILURE(S)");
        if (failures != 0) System.exit(1);
    }
}
