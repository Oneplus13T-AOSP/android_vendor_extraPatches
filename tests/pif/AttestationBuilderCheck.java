import android.security.trickystore.AttestationExtensionBuilder;

import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Host-side checks for the attestation extension encoder. These assert the invariants
 * Play Integrity actually inspects: tag presence, ascending order, RootOfTrust shape,
 * and that the identity written is the spoofed profile rather than the request values.
 */
public class AttestationBuilderCheck {
    static int failures = 0;

    static void check(boolean cond, String what) {
        if (!cond) {
            failures++;
            System.out.println("FAIL: " + what);
        } else {
            System.out.println("ok:   " + what);
        }
    }

    static byte[] b(String s) { return s.getBytes(java.nio.charset.StandardCharsets.UTF_8); }

    public static void main(String[] args) {
        AttestationExtensionBuilder.Params p = new AttestationExtensionBuilder.Params();
        p.algorithm = 3;          // EC
        p.keySize = 256;
        p.ecCurve = 3;            // P_256
        p.purpose = new ArrayList<>(List.of(2));       // SIGN
        p.digest = new ArrayList<>(List.of(4));        // SHA-256
        p.challenge = new byte[] {1, 2, 3, 4};
        p.bootKey = hex("11".repeat(32));
        p.bootHash = hex("22".repeat(32));
        p.patchLevels = new int[] {202609, 20260905, 20260905};
        p.osVersion = 170000;
        p.attestVersion = 400;
        p.keymasterVersion = 400;
        p.brand = b("google");
        p.device = b("blazer");
        p.product = b("blazer_beta");
        p.manufacturer = b("Google");
        p.model = b("Pixel 10 Pro");

        Extension ext = AttestationExtensionBuilder.build(p);
        ASN1Sequence kd = AttestationExtensionBuilder.decodeKeyDescription(ext);
        check(kd != null && kd.size() == 8, "KeyDescription has 8 fields");

        List<Integer> tee = AttestationExtensionBuilder.tagNumbers(kd, 7);
        List<Integer> sw = AttestationExtensionBuilder.tagNumbers(kd, 6);

        for (int tag : new int[] {1, 2, 3, 5, 10, 503, 702, 704, 705, 706, 710, 711, 712,
                716, 717, 718, 719}) {
            check(tee.contains(tag), "teeEnforced contains tag " + tag);
        }
        check(sw.contains(701), "softwareEnforced contains creation datetime 701");

        List<Integer> sorted = new ArrayList<>(tee);
        sorted.sort(Integer::compare);
        check(tee.equals(sorted), "teeEnforced tags are in ascending order");

        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 710), b("google")),
                "710 brand is the profile value");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 711), b("blazer")),
                "711 device is the profile value");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 712), b("blazer_beta")),
                "712 product is the profile value");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 716), b("Google")),
                "716 manufacturer is the profile value");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 717), b("Pixel 10 Pro")),
                "717 model is the profile value");

        // Physical identifiers must never be signed.
        for (int tag : new int[] {713, 714, 715, 723}) {
            check(!tee.contains(tag), "physical identifier tag " + tag + " is absent");
        }

        byte[][] rot = AttestationExtensionBuilder.rootOfTrust(kd);
        check(rot != null, "RootOfTrust present");
        check(rot != null && Arrays.equals(rot[0], hex("11".repeat(32))),
                "RootOfTrust boot key preserved");
        check(rot != null && Arrays.equals(rot[1], hex("22".repeat(32))),
                "RootOfTrust boot hash preserved");

        check(AttestationExtensionBuilder.integer(kd, 7, 706)
                        .equals(BigInteger.valueOf(202609)),
                "system patch level 706 is YYYYMM");
        check(AttestationExtensionBuilder.integer(kd, 7, 718)
                        .equals(BigInteger.valueOf(20260905)),
                "vendor patch level 718 is YYYYMMDD");
        check(AttestationExtensionBuilder.integer(kd, 7, 719)
                        .equals(BigInteger.valueOf(20260905)),
                "boot patch level 719 is YYYYMMDD");
        check(AttestationExtensionBuilder.integer(kd, 7, 705)
                        .equals(BigInteger.valueOf(170000)),
                "osVersion 705 is the API-derived value");

        // No identity: the tags must be omitted rather than signed empty.
        AttestationExtensionBuilder.Params q = new AttestationExtensionBuilder.Params();
        q.algorithm = 3; q.keySize = 256; q.ecCurve = 3;
        q.osVersion = 170000; q.attestVersion = 400; q.keymasterVersion = 400;
        ASN1Sequence kd2 = AttestationExtensionBuilder.decodeKeyDescription(
                AttestationExtensionBuilder.build(q));
        List<Integer> tee2 = AttestationExtensionBuilder.tagNumbers(kd2, 7);
        for (int tag : new int[] {710, 711, 712, 716, 717}) {
            check(!tee2.contains(tag), "no profile: identity tag " + tag + " is absent");
        }

        // RSA: exponent and no EC curve tag.
        AttestationExtensionBuilder.Params r = new AttestationExtensionBuilder.Params();
        r.algorithm = 1; r.keySize = 2048;
        r.rsaPublicExponent = BigInteger.valueOf(65537);
        r.osVersion = 170000; r.attestVersion = 400; r.keymasterVersion = 400;
        ASN1Sequence kd3 = AttestationExtensionBuilder.decodeKeyDescription(
                AttestationExtensionBuilder.build(r));
        List<Integer> tee3 = AttestationExtensionBuilder.tagNumbers(kd3, 7);
        check(tee3.contains(200), "RSA reports the public exponent as 200");
        check(!tee3.contains(10), "RSA does not report an EC curve");

        System.out.println();
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " FAILURE(S)");
        if (failures != 0) System.exit(1);
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
