import android.security.trickystore.AttestationExtensionBuilder;
import android.security.trickystore.KeyBoxManager;

import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;

/**
 * Host-side checks for keybox parsing, using a synthetic keybox whose private keys
 * this test generates. Verifies that the parser accepts the RKP single-algorithm
 * shape, rejects mismatched material, links every certificate by issuer signature,
 * and that the material it produces actually signs a verifying leaf.
 */
public class KeyboxCheck {
    static int failures = 0;

    static void check(boolean cond, String what) {
        if (!cond) {
            failures++;
            System.out.println("FAIL: " + what);
        } else {
            System.out.println("ok:   " + what);
        }
    }

    public static void main(String[] args) throws Exception {
        // ---- Build a two-algorithm keybox from generated material.
        KeyPair ecIssuer = ecKeyPair();
        KeyPair rsaIssuer = rsaKeyPair();
        X509Certificate ecRoot = selfSigned(ecIssuer, "CN=EC Root");
        X509Certificate ecLeaf = signed(ecIssuer, ecRoot, "CN=EC TEE, O=TEE");
        X509Certificate rsaRoot = selfSigned(rsaIssuer, "CN=RSA Root");
        X509Certificate rsaLeaf = signed(rsaIssuer, rsaRoot, "CN=RSA TEE, O=TEE");

        String dual = keyboxXml(
                pem("EC PRIVATE KEY", ecIssuer.getPrivate().getEncoded()),
                new X509Certificate[] {ecLeaf, ecRoot},
                pem("RSA PRIVATE KEY", rsaIssuer.getPrivate().getEncoded()),
                new X509Certificate[] {rsaLeaf, rsaRoot});

        KeyBoxManager manager = new KeyBoxManager();
        check(manager.parseKeybox(dual), "dual-algorithm keybox parses");
        check(manager.hasKeyboxes(), "keyboxes loaded");
        check(manager.getKeybox("EC") != null, "EC keybox present");
        check(manager.getKeybox("RSA") != null, "RSA keybox present");
        check(manager.getKeyboxForLeaf("EC").algorithm.equals("EC"),
                "EC leaf uses the EC issuer");
        check(manager.getKeyboxForLeaf("RSA").algorithm.equals("RSA"),
                "RSA leaf uses the RSA issuer");

        // ---- The leaf this keybox signs must verify against its issuer cert.
        KeyPair subject = ecKeyPair();
        X509Certificate signedLeaf = signLeaf(manager.getKeybox("EC"), subject, "CN=Subject");
        signedLeaf.verify(ecLeaf.getPublicKey());
        check(true, "leaf signed by the EC keybox verifies against the issuer");

        // ---- RKP shape: one ECDSA key only.
        String ecOnly = keyboxXml(
                pem("EC PRIVATE KEY", ecIssuer.getPrivate().getEncoded()),
                new X509Certificate[] {ecLeaf, ecRoot}, null, null);
        KeyBoxManager rkp = new KeyBoxManager();
        check(rkp.parseKeybox(ecOnly), "EC-only (RKP shape) keybox parses");
        check(rkp.getKeybox("EC") != null, "EC-only keybox has an EC entry");
        check(rkp.getKeybox("RSA") == null, "EC-only keybox has no RSA entry");
        check(rkp.getKeyboxForLeaf("RSA") != null
                        && rkp.getKeyboxForLeaf("RSA").algorithm.equals("EC"),
                "EC-only keybox still signs an RSA leaf");

        // An RSA-subject leaf signed by the EC issuer must verify: the issuer key
        // algorithm does not have to match the subject key algorithm.
        KeyPair rsaSubject = rsaKeyPair();
        X509Certificate crossSigned = signLeaf(rkp.getKeyboxForLeaf("RSA"), rsaSubject, "CN=RSA Subject");
        crossSigned.verify(ecLeaf.getPublicKey());
        check(true, "RSA leaf signed by the EC-only keybox verifies");

        // ---- Rejections.
        String mismatched = keyboxXml(
                pem("EC PRIVATE KEY", ecIssuer.getPrivate().getEncoded()),
                new X509Certificate[] {ecLeaf, ecRoot},
                pem("RSA PRIVATE KEY", rsaKeyPair().getPrivate().getEncoded()),
                new X509Certificate[] {rsaLeaf, rsaRoot});
        KeyBoxManager bad = new KeyBoxManager();
        bad.parseKeybox(mismatched);
        check(bad.getKeybox("RSA") == null,
                "keybox with a private key that does not match its certificate is rejected");

        String brokenChain = keyboxXml(
                pem("EC PRIVATE KEY", ecIssuer.getPrivate().getEncoded()),
                new X509Certificate[] {ecLeaf, rsaRoot}, null, null);
        KeyBoxManager badChain = new KeyBoxManager();
        badChain.parseKeybox(brokenChain);
        check(!badChain.hasKeyboxes(), "keybox with an unlinked certificate chain is rejected");

        KeyBoxManager truncated = new KeyBoxManager();
        String half = dual.substring(0, dual.length() / 2);
        check(!truncated.parseKeybox(half), "truncated keybox is rejected");
        check(!truncated.hasKeyboxes(), "truncated keybox leaves nothing loaded");

        truncated.parseKeybox(ecOnly);
        check(truncated.hasKeyboxes(), "good keybox after a bad one loads");
        // Reloading a cut-off document must keep the previous material.
        check(!truncated.parseKeybox(half), "cut-off keybox after a good one is rejected");
        check(truncated.getKeybox("EC") != null,
                "a cut-off document keeps the previously loaded keybox");
        truncated.parseKeybox("<AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes>"
                + "</AndroidAttestation>");
        check(truncated.getKeybox("EC") != null,
                "a keyless document keeps the previously loaded keybox");

        // ---- Attestation extension carrying the profile identity.
        AttestationExtensionBuilder.Params p = new AttestationExtensionBuilder.Params();
        p.algorithm = 3; p.keySize = 256; p.ecCurve = 3;
        p.osVersion = 170000; p.attestVersion = 400; p.keymasterVersion = 400;
        p.bootKey = new byte[32]; p.bootHash = new byte[32];
        Extension ext = AttestationExtensionBuilder.build(p);
        ASN1Sequence kd = AttestationExtensionBuilder.decodeKeyDescription(ext);
        check(kd != null, "attestation extension decodes");

        System.out.println();
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " FAILURE(S)");
        if (failures != 0) System.exit(1);
    }

    // ---------------------------------------------------------------- helpers

    static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    static X509Certificate selfSigned(KeyPair kp, String dn) throws Exception {
        return build(kp, kp.getPrivate(), dn, dn);
    }

    static X509Certificate signed(KeyPair issuer, X509Certificate issuerCert, String dn)
            throws Exception {
        return build(issuer, issuer.getPrivate(), issuerCert.getSubjectX500Principal().getName(),
                dn);
    }

    /** Builds a certificate for [subject] signed by [issuerKey] / [issuer]. */
    static X509Certificate issuedTo(KeyPair subject, KeyPair issuerKey,
            X509Certificate issuer, String dn) throws Exception {
        return build(subject, issuerKey.getPrivate(),
                issuer.getSubjectX500Principal().getName(), dn);
    }

    static X509Certificate build(KeyPair subject, java.security.PrivateKey signer,
            String issuerDn, String subjectDn) throws Exception {
        com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder b =
                new com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder(
                        new com.android.internal.org.bouncycastle.asn1.x500.X500Name(issuerDn),
                        java.math.BigInteger.valueOf(System.nanoTime()),
                        new java.util.Date(System.currentTimeMillis() - 86400000L),
                        new java.util.Date(System.currentTimeMillis() + 86400000L),
                        new com.android.internal.org.bouncycastle.asn1.x500.X500Name(subjectDn),
                        com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                                subject.getPublic().getEncoded()));
        String alg = signer.getAlgorithm().equalsIgnoreCase("EC")
                ? "SHA256withECDSA" : "SHA256withRSA";
        com.android.internal.org.bouncycastle.operator.ContentSigner cs =
                new com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(alg).build(signer);
        byte[] der = b.build(cs).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    static X509Certificate signLeaf(KeyBoxManager.KeyBox box, KeyPair subject, String dn)
            throws Exception {
        com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder b =
                new com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder(
                        box.getIssuerSubject(),
                        java.math.BigInteger.valueOf(System.nanoTime()),
                        new java.util.Date(System.currentTimeMillis() - 1000L),
                        new java.util.Date(System.currentTimeMillis() + 86400000L),
                        new com.android.internal.org.bouncycastle.asn1.x500.X500Name(dn),
                        com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                                subject.getPublic().getEncoded()));
        String alg = box.algorithm.equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        com.android.internal.org.bouncycastle.operator.ContentSigner cs =
                new com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(alg)
                        .build(box.keyPair.getPrivate());
        byte[] der = b.build(cs).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    static String certPem(X509Certificate cert) throws Exception {
        return pem("CERTIFICATE", cert.getEncoded());
    }

    static String keyboxXml(String ecPriv, X509Certificate[] ecChain,
            String rsaPriv, X509Certificate[] rsaChain) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\"?>\n<AndroidAttestation>\n<NumberOfKeyboxes>1</NumberOfKeyboxes>\n");
        sb.append("<Keybox DeviceID=\"Test\">\n");
        if (ecPriv != null) {
            sb.append("<Key algorithm=\"ecdsa\">\n<PrivateKey format=\"pem\">\n")
                    .append(ecPriv).append("</PrivateKey>\n<CertificateChain>\n");
            for (X509Certificate c : ecChain) {
                sb.append("<Certificate format=\"pem\">\n").append(certPem(c))
                        .append("</Certificate>\n");
            }
            sb.append("</CertificateChain>\n</Key>\n");
        }
        if (rsaPriv != null) {
            sb.append("<Key algorithm=\"rsa\">\n<PrivateKey format=\"pem\">\n")
                    .append(rsaPriv).append("</PrivateKey>\n<CertificateChain>\n");
            for (X509Certificate c : rsaChain) {
                sb.append("<Certificate format=\"pem\">\n").append(certPem(c))
                        .append("</Certificate>\n");
            }
            sb.append("</CertificateChain>\n</Key>\n");
        }
        sb.append("</Keybox>\n</AndroidAttestation>\n");
        return sb.toString();
    }
}
