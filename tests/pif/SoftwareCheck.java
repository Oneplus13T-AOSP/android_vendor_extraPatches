import android.security.trickystore.AttestationExtensionBuilder;
import android.security.trickystore.CertificateGenerator;
import android.security.trickystore.KeyBoxManager;
import android.security.trickystore.LeafCertificateBuilder;

import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.KeyUsage;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Host-side check of the software certificate-generation path used when the TEE
 * cannot attest at all (Mode.GENERATE, or AUTO on a device whose TEE fails).
 */
public class SoftwareCheck {
    static int failures = 0;

    static void check(boolean c, String what) {
        if (!c) { failures++; System.out.println("FAIL: " + what); }
        else System.out.println("ok:   " + what);
    }

    static byte[] b(String s) { return s.getBytes(java.nio.charset.StandardCharsets.UTF_8); }

    public static void main(String[] args) throws Exception {
        KeyPair rootKey = KeyboxCheck.ecKeyPair();
        X509Certificate root = KeyboxCheck.selfSigned(rootKey, "CN=EC Root");
        KeyPair issuerKey = KeyboxCheck.ecKeyPair();
        X509Certificate issuer = KeyboxCheck.issuedTo(
                issuerKey, rootKey, root, "CN=EC TEE, O=TEE");

        String xml = KeyboxCheck.keyboxXml(
                KeyboxCheck.pem("EC PRIVATE KEY", issuerKey.getPrivate().getEncoded()),
                new X509Certificate[] {issuer, root}, null, null);
        KeyBoxManager keybox = new KeyBoxManager();
        check(keybox.parseKeybox(xml), "keybox loads for software generation");

        // ---- EC leaf, as KeyMint would ask for a P-256 attestation.
        KeyPair subject = ec();
        AttestationExtensionBuilder.Params p = new AttestationExtensionBuilder.Params();
        p.algorithm = 3; p.keySize = 256; p.ecCurve = 3;
        p.purpose = new ArrayList<>(List.of(2));
        p.digest = new ArrayList<>(List.of(4));
        p.challenge = b("gms-challenge");
        p.bootKey = new byte[32]; p.bootHash = new byte[32];
        p.patchLevels = new int[] {202609, 20260905, 20260905};
        p.osVersion = 170000; p.attestVersion = 400; p.keymasterVersion = 400;
        p.brand = b("google"); p.device = b("blazer");
        p.product = b("blazer_beta"); p.manufacturer = b("Google");
        p.model = b("Pixel 10 Pro");

        X509Certificate leaf = LeafCertificateBuilder.build(
                subject, keybox.getKeybox("EC"),
                BigInteger.valueOf(12345),
                new Date(System.currentTimeMillis() - 1000L),
                new Date(System.currentTimeMillis() + 86400000L),
                new X500Name("CN=Android Keystore Key"),
                KeyUsage.digitalSignature,
                AttestationExtensionBuilder.build(p));

        check(leaf != null, "software leaf generated");
        // A fixed serial on every device is a software-certificate fingerprint; KeyMint
        // issues a random one per key, so two leaves must not share a serial.
        java.security.KeyPair subject2 = ec();
        X509Certificate leaf2 = LeafCertificateBuilder.build(
                subject2, keybox.getKeybox("EC"),
                java.math.BigInteger.valueOf(99999),
                new Date(System.currentTimeMillis() - 1000L),
                new Date(System.currentTimeMillis() + 86400000L),
                new X500Name("CN=Android Keystore Key"),
                KeyUsage.digitalSignature,
                AttestationExtensionBuilder.build(p));
        check(leaf.getSerialNumber().signum() > 0, "leaf serial is positive");
        check(!leaf2.getSerialNumber().equals(leaf.getSerialNumber()),
                "distinct leaves get distinct serials");
        check(BcCryptoShim.verify(leaf.getSigAlgName(), issuer.getPublicKey(),
                        leaf.getTBSCertificate(), leaf.getSignature()),
                "software leaf verifies against the keybox issuer");
        check(leaf.getPublicKey().equals(subject.getPublic()),
                "software leaf carries the generated subject key");
        check(leaf.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()),
                "software leaf issuer DN is the keybox subject");

        ASN1Sequence kd = AttestationExtensionBuilder.decodeKeyDescription(
                new Extension(AttestationExtensionBuilder.ATTESTATION_OID, false,
                        new com.android.internal.org.bouncycastle.asn1.DEROctetString(
                                ASN1Sequence.getInstance(
                                        com.android.internal.org.bouncycastle.asn1.ASN1OctetString
                                                .getInstance(
                                                        com.android.internal.org.bouncycastle.asn1.ASN1Primitive
                                                                .fromByteArray(leaf.getExtensionValue(
                                                                        AttestationExtensionBuilder.ATTESTATION_OID.getId())))
                                                .getOctets()).getEncoded())));
        check(kd != null, "software leaf carries a decodable attestation extension");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 710), b("google")),
                "software leaf attests the profile brand");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 717), b("Pixel 10 Pro")),
                "software leaf attests the profile model");
        List<Integer> tee = AttestationExtensionBuilder.tagNumbers(kd, 7);
        for (int tag : new int[] {713, 714, 715, 723}) {
            check(!tee.contains(tag), "software leaf omits physical identifier " + tag);
        }

        // ---- RSA leaf signed by the same EC keybox (cross-algorithm issuer).
        KeyPair rsaSubject = KeyboxCheck.rsaKeyPair();
        AttestationExtensionBuilder.Params r = new AttestationExtensionBuilder.Params();
        r.algorithm = 1; r.keySize = 2048;
        r.rsaPublicExponent = BigInteger.valueOf(65537);
        r.purpose = new ArrayList<>(List.of(2));
        r.digest = new ArrayList<>(List.of(4));
        r.bootKey = new byte[32]; r.bootHash = new byte[32];
        r.osVersion = 170000; r.attestVersion = 400; r.keymasterVersion = 400;

        X509Certificate rsaLeaf = LeafCertificateBuilder.build(
                rsaSubject, keybox.getKeyboxForLeaf("RSA"),
                BigInteger.valueOf(67890),
                new Date(System.currentTimeMillis() - 1000L),
                new Date(System.currentTimeMillis() + 86400000L),
                new X500Name("CN=Android Keystore Key"),
                KeyUsage.digitalSignature,
                AttestationExtensionBuilder.build(r));
        check(BcCryptoShim.verify(rsaLeaf.getSigAlgName(), issuer.getPublicKey(),
                        rsaLeaf.getTBSCertificate(), rsaLeaf.getSignature()),
                "RSA software leaf verifies against the EC keybox issuer");
        check(rsaLeaf.getPublicKey() instanceof java.security.interfaces.RSAPublicKey,
                "RSA software leaf keeps an RSA subject key");

        // ---- An RSA keybox must sign an EC leaf the same way.
        KeyPair rsaRootKey = KeyboxCheck.rsaKeyPair();
        X509Certificate rsaRoot = KeyboxCheck.selfSigned(rsaRootKey, "CN=RSA Root");
        KeyPair rsaIssuerKey = KeyboxCheck.rsaKeyPair();
        X509Certificate rsaIssuer = KeyboxCheck.issuedTo(
                rsaIssuerKey, rsaRootKey, rsaRoot, "CN=RSA TEE, O=TEE");
        String rsaXml = KeyboxCheck.keyboxXml(null, null,
                KeyboxCheck.pem("RSA PRIVATE KEY", rsaIssuerKey.getPrivate().getEncoded()),
                new X509Certificate[] {rsaIssuer, rsaRoot});
        KeyBoxManager rsaBox = new KeyBoxManager();
        check(rsaBox.parseKeybox(rsaXml), "RSA-only keybox loads");
        KeyPair ecSubject = ec();
        X509Certificate ecLeaf = LeafCertificateBuilder.build(
                ecSubject, rsaBox.getKeyboxForLeaf("EC"),
                BigInteger.TEN,
                new Date(System.currentTimeMillis() - 1000L),
                new Date(System.currentTimeMillis() + 86400000L),
                new X500Name("CN=Android Keystore Key"),
                KeyUsage.digitalSignature,
                AttestationExtensionBuilder.build(p));
        check(BcCryptoShim.verify(ecLeaf.getSigAlgName(), rsaIssuer.getPublicKey(),
                        ecLeaf.getTBSCertificate(), ecLeaf.getSignature()),
                "EC leaf verifies against an RSA-only keybox issuer");

        // Generated serials must be positive, distinct, and not the old fixed 1.
        java.math.BigInteger a = CertificateGenerator.generateRandomSerial();
        java.math.BigInteger b = CertificateGenerator.generateRandomSerial();
        check(a.signum() > 0, "generated serial is positive");
        check(b.signum() > 0, "second generated serial is positive");
        check(!a.equals(b), "generated serials differ");
        check(!a.equals(java.math.BigInteger.ONE),
                "generated serial is not the old fixed value 1");
        check(a.bitLength() >= 60, "generated serial uses the full range");

        System.out.println();
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " FAILURE(S)");
        if (failures != 0) System.exit(1);
    }

    static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }
}
