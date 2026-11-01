import android.security.trickystore.AttestationExtensionBuilder;
import android.security.trickystore.KeyBoxManager;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERNull;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERSet;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.KeyUsage;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.TreeMap;

/**
 * Host-side check of the hardware-leaf re-signing path, which is the one that
 * produces a STRONG verdict on a device with a working TEE.
 *
 * <p>Simulates a KeyMint leaf: TEE-signed, carrying the handset's real ODM identity
 * (OnePlus/PHB110), a real serial, a real IMEI and the genuine RootOfTrust. Then
 * applies the same rewriting the framework does and asserts the result.
 */
public class HackerCheck {
    static int failures = 0;

    static void check(boolean c, String what) {
        if (!c) { failures++; System.out.println("FAIL: " + what); }
        else System.out.println("ok:   " + what);
    }

    static byte[] b(String s) { return s.getBytes(java.nio.charset.StandardCharsets.UTF_8); }
    static byte[] hex(String s) {
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(s.substring(i*2,i*2+2),16);
        return o;
    }

    public static void main(String[] args) throws Exception {
        KeyPair teeKey = ec();
        KeyPair hardwareIssuerKey = ec();
        X509Certificate hardwareIssuer = selfSigned(hardwareIssuerKey, "CN=Hardware Root");

        // The real verified-boot values the TEE measured.
        byte[] realBootKey = hex("aa".repeat(32));
        byte[] realBootHash = hex("bb".repeat(32));

        X509Certificate hardwareLeaf = hardwareLeaf(
                teeKey, hardwareIssuerKey, hardwareIssuer,
                realBootKey, realBootHash);

        // Sanity: the simulated hardware leaf looks like the device we are fixing.
        ASN1Sequence original = AttestationExtensionBuilder.decodeKeyDescription(
                extension(hardwareLeaf));
        check(Arrays.equals(AttestationExtensionBuilder.octets(original, 7, 710), b("OnePlus")),
                "simulated leaf attests the real ODM brand (OnePlus)");
        check(AttestationExtensionBuilder.tagNumbers(original, 7).contains(713),
                "simulated leaf attests a serial number");
        check(AttestationExtensionBuilder.tagNumbers(original, 7).contains(714),
                "simulated leaf attests an IMEI");

        // Hardware leaf signed by the TEE verifies before rewriting.
        check(verify(hardwareIssuer.getPublicKey(), hardwareLeaf),
                "simulated hardware leaf verifies against the TEE issuer");

        // ---- Build a keybox issuer and run the real rewriter.
        // A real keybox: cert[0] is issued to the keybox private key's public key,
        // cert[1] is the root that signed it.
        KeyPair rootKey = ec();
        X509Certificate ecRoot = selfSigned(rootKey, "CN=EC Root");
        KeyPair ecIssuer = ec();
        X509Certificate ecLeafIssuer = issuedTo(ecIssuer, rootKey, ecRoot, "CN=EC TEE, O=TEE");
        String xml = KeyboxCheck.keyboxXml(
                KeyboxCheck.pem("EC PRIVATE KEY", ecIssuer.getPrivate().getEncoded()),
                new X509Certificate[] {ecLeafIssuer, ecRoot}, null, null);
        KeyBoxManager keybox = new KeyBoxManager();
        check(keybox.parseKeybox(xml), "keybox for the rewriter loads");

        android.security.trickystore.AttestationLeafRewriter.Inputs in =
                new android.security.trickystore.AttestationLeafRewriter.Inputs();
        in.identity = new java.util.HashMap<>();
        in.identity.put(710, b("google"));
        in.identity.put(711, b("blazer"));
        in.identity.put(712, b("blazer_beta"));
        in.identity.put(716, b("Google"));
        in.identity.put(717, b("Pixel 10 Pro"));
        in.bootKey = realBootKey;
        in.bootHash = realBootHash;
        in.patchLevels = new int[] {202609, 20260905, 20260905};
        in.osVersion = 170000;

        Certificate[] out = android.security.trickystore.AttestationLeafRewriter.rewrite(
                new Certificate[] {hardwareLeaf, hardwareIssuer},
                keybox.getKeybox("EC"), in);
        // The rewritten chain is the new leaf plus the whole keybox chain (issuer + root),
        // because attestation verification has to terminate at the keybox root.
        check(out != null && out.length == 3, "rewrite returns leaf + the full keybox chain");
        if (out == null || out.length < 2 || !(out[0] instanceof X509Certificate)) {
            System.out.println("FAIL: no rewritten leaf"); System.exit(1);
        }
        X509Certificate rewritten = (X509Certificate) out[0];

        check(rewritten != hardwareLeaf, "the leaf object was replaced");
        check(Arrays.equals(((X509Certificate) out[1]).getEncoded(),
                        ecLeafIssuer.getEncoded()),
                "chain[1] is the keybox issuer certificate");
        check(Arrays.equals(((X509Certificate) out[2]).getEncoded(),
                        ecRoot.getEncoded()),
                "chain[2] is the keybox root certificate");
        check(!Arrays.equals(((X509Certificate) out[1]).getEncoded(),
                        hardwareIssuer.getEncoded()),
                "the original TEE issuer certificate is no longer in the chain");
        check(verify(ecLeafIssuer.getPublicKey(), rewritten),
                "rewritten leaf verifies against the keybox issuer");
        check(!verify(hardwareIssuer.getPublicKey(), rewritten),
                "rewritten leaf no longer verifies against the TEE issuer");

        ASN1Sequence kd = AttestationExtensionBuilder.decodeKeyDescription(
                extension(rewritten));
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 710), b("google")),
                "rewritten 710 BRAND is the profile value");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 711), b("blazer")),
                "rewritten 711 DEVICE is the profile value");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 712), b("blazer_beta")),
                "rewritten 712 PRODUCT is the profile value");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 716), b("Google")),
                "rewritten 716 MANUFACTURER is the profile value");
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd, 7, 717), b("Pixel 10 Pro")),
                "rewritten 717 MODEL is the profile value");

        List<Integer> tee = AttestationExtensionBuilder.tagNumbers(kd, 7);
        check(!tee.contains(713), "rewritten certificate drops the serial (713)");
        check(!tee.contains(714), "rewritten certificate drops the IMEI (714)");

        byte[][] rot = AttestationExtensionBuilder.rootOfTrust(kd);
        check(rot != null && Arrays.equals(rot[0], realBootKey),
                "RootOfTrust boot key is the genuine TEE value");
        check(rot != null && Arrays.equals(rot[1], realBootHash),
                "RootOfTrust boot hash is the genuine TEE value");

        check(AttestationExtensionBuilder.integer(kd, 7, 706)
                        .equals(java.math.BigInteger.valueOf(202609)),
                "rewritten system patch level follows the configuration");
        check(AttestationExtensionBuilder.integer(kd, 7, 718)
                        .equals(java.math.BigInteger.valueOf(20260905)),
                "rewritten vendor patch level follows the configuration");

        List<Integer> sorted = new ArrayList<>(tee);
        sorted.sort(Integer::compare);
        check(tee.equals(sorted), "rewritten tags stay in ascending order");
        check(new java.util.HashSet<>(tee).size() == tee.size(),
                "no duplicate tags after rewriting");

        // The leaf key must not change: only the certificate is re-signed.
        check(rewritten.getPublicKey().equals(hardwareLeaf.getPublicKey()),
                "the attested public key is preserved");

        // Re-running the rewrite on its own output must be a no-op.
        Certificate[] again = android.security.trickystore.AttestationLeafRewriter.rewrite(
                out, keybox.getKeybox("EC"), in);
        check(again == out, "re-signing an already keybox-signed leaf is a no-op");

        // No identity configured: the TEE-reported identity is left in place.
        android.security.trickystore.AttestationLeafRewriter.Inputs empty =
                new android.security.trickystore.AttestationLeafRewriter.Inputs();
        empty.bootKey = realBootKey; empty.bootHash = realBootHash;
        empty.patchLevels = in.patchLevels; empty.osVersion = 170000;
        Certificate[] untouched = android.security.trickystore.AttestationLeafRewriter.rewrite(
                new Certificate[] {hardwareLeaf, hardwareIssuer},
                keybox.getKeybox("EC"), empty);
        ASN1Sequence kd2 = AttestationExtensionBuilder.decodeKeyDescription(
                extension((X509Certificate) untouched[0]));
        check(Arrays.equals(AttestationExtensionBuilder.octets(kd2, 7, 710), b("OnePlus")),
                "with no profile the hardware identity is kept");
        check(!AttestationExtensionBuilder.tagNumbers(kd2, 7).contains(713),
                "with no profile the serial is still dropped");

        System.out.println();
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " FAILURE(S)");
        if (failures != 0) System.exit(1);
    }

    static Extension extension(X509Certificate cert) throws Exception {
        byte[] raw = cert.getExtensionValue(AttestationExtensionBuilder.ATTESTATION_OID.getId());
        com.android.internal.org.bouncycastle.asn1.ASN1OctetString outer =
                com.android.internal.org.bouncycastle.asn1.ASN1OctetString.getInstance(
                        com.android.internal.org.bouncycastle.asn1.ASN1Primitive.fromByteArray(raw));
        ASN1Sequence kd = ASN1Sequence.getInstance(outer.getOctets());
        return new Extension(AttestationExtensionBuilder.ATTESTATION_OID, false,
                new DEROctetString(kd.getEncoded()));
    }

    /** Builds a KeyMint-shaped leaf: ascending tags, real identity, real RootOfTrust. */
    static X509Certificate hardwareLeaf(KeyPair subject, KeyPair issuerKey,
            X509Certificate issuer, byte[] bootKey, byte[] bootHash) throws Exception {
        TreeMap<Integer, ASN1Encodable> tee = new TreeMap<>();
        tee.put(1, new DERSet(new ASN1Integer(2)));
        tee.put(2, new ASN1Integer(3));
        tee.put(3, new ASN1Integer(256));
        tee.put(5, new DERSet(new ASN1Integer(4)));
        tee.put(10, new ASN1Integer(3));
        tee.put(503, DERNull.INSTANCE);
        tee.put(702, new ASN1Integer(0));
        tee.put(704, new DERSequence(new ASN1Encodable[] {
                new DEROctetString(bootKey), ASN1Boolean.TRUE,
                new ASN1Enumerated(0), new DEROctetString(bootHash)}));
        tee.put(705, new ASN1Integer(170000));
        tee.put(706, new ASN1Integer(202508));
        tee.put(710, new DEROctetString(b("OnePlus")));
        tee.put(711, new DEROctetString(b("OP591BL1")));
        tee.put(712, new DEROctetString(b("PHB110")));
        tee.put(713, new DEROctetString(b("6a35ed7d")));
        tee.put(714, new DEROctetString(b("861234567890123")));
        tee.put(716, new DEROctetString(b("OnePlus")));
        tee.put(717, new DEROctetString(b("PHB110")));
        tee.put(718, new ASN1Integer(20250805));
        tee.put(719, new ASN1Integer(20250805));

        TreeMap<Integer, ASN1Encodable> sw = new TreeMap<>();
        sw.put(701, new ASN1Integer(System.currentTimeMillis()));

        ASN1Sequence kd = new DERSequence(new ASN1Encodable[] {
                new ASN1Integer(400), new ASN1Enumerated(1),
                new ASN1Integer(400), new ASN1Enumerated(1),
                new DEROctetString(b("challenge")), new DEROctetString(new byte[0]),
                authList(sw), authList(tee)});
        Extension ext = new Extension(AttestationExtensionBuilder.ATTESTATION_OID, false,
                new DEROctetString(kd.getEncoded()));

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name(issuer.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.nanoTime()),
                new java.util.Date(System.currentTimeMillis() - 1000L),
                new java.util.Date(System.currentTimeMillis() + 86400000L),
                new X500Name("CN=Android Keystore Key"),
                SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded()));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(ext);

        ContentSigner signer = BcCryptoShim.newSigner(
                "SHA256withECDSA", issuerKey.getPrivate());
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(
                        builder.build(signer).getEncoded()));
    }

    static DERSequence authList(TreeMap<Integer, ASN1Encodable> fields) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (var e : fields.entrySet()) v.add(new DERTaggedObject(true, e.getKey(), e.getValue()));
        return new DERSequence(v);
    }

    static boolean verify(java.security.PublicKey key, X509Certificate cert) throws Exception {
        return BcCryptoShim.verify(cert.getSigAlgName(), key,
                cert.getTBSCertificate(), cert.getSignature());
    }

    static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static X509Certificate issuedTo(KeyPair subject, KeyPair issuerKey,
            X509Certificate issuer, String dn) throws Exception {
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                new X500Name(issuer.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.nanoTime()),
                new java.util.Date(System.currentTimeMillis() - 86400000L),
                new java.util.Date(System.currentTimeMillis() + 86400000L),
                new X500Name(dn),
                SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded()));
        ContentSigner cs = BcCryptoShim.newSigner(
                "SHA256withECDSA", issuerKey.getPrivate());
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(b.build(cs).getEncoded()));
    }

    static X509Certificate selfSigned(KeyPair kp, String dn) throws Exception {
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                new X500Name(dn), BigInteger.valueOf(System.nanoTime()),
                new java.util.Date(System.currentTimeMillis() - 86400000L),
                new java.util.Date(System.currentTimeMillis() + 86400000L),
                new X500Name(dn),
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
        ContentSigner cs = BcCryptoShim.newSigner(
                "SHA256withECDSA", kp.getPrivate());
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(b.build(cs).getEncoded()));
    }
}
