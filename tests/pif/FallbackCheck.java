import android.hardware.security.keymint.*;
import android.security.*;
import android.security.trickystore.*;
import android.system.keystore2.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

public class FallbackCheck {
    static void check(boolean value, String name) {
        if (!value) throw new AssertionError(name);
        System.out.println("ok: " + name);
    }
    static KeyParameter p(int tag, KeyParameterValue value) {
        KeyParameter p = new KeyParameter(); p.tag = tag; p.value = value; return p;
    }
    static KeyMetadata recover(KeyStoreSecurityLevel backend, KeyDescriptor descriptor,
            List<KeyParameter> request, int error) {
        return KeyboxGenerationFallback.tryGenerate(backend, SecurityLevel.TRUSTED_ENVIRONMENT,
                descriptor, null, request, 0, new android.security.KeyStoreException(error, "hardware failure"));
    }
    public static void main(String[] argv) throws Exception {
        KeyDescriptor descriptor = new KeyDescriptor();
        descriptor.domain = Domain.APP; descriptor.alias = "app-key";
        List<KeyParameter> request = new ArrayList<>(List.of(
                p(Tag.ALGORITHM, KeyParameterValue.algorithm(Algorithm.EC)),
                p(Tag.EC_CURVE, KeyParameterValue.ecCurve(EcCurve.P_256)),
                p(Tag.PURPOSE, KeyParameterValue.keyPurpose(KeyPurpose.SIGN)),
                p(Tag.DIGEST, KeyParameterValue.digest(4)),
                p(Tag.ATTESTATION_CHALLENGE, KeyParameterValue.blob(new byte[] {1,2,3})),
                p(Tag.ATTESTATION_ID_SERIAL, KeyParameterValue.blob(new byte[] {9})),
                p(Tag.ATTESTATION_ID_IMEI, KeyParameterValue.blob(new byte[] {8})),
                p(Tag.CERTIFICATE_NOT_BEFORE, KeyParameterValue.dateTime(0)),
                p(Tag.CERTIFICATE_NOT_AFTER, KeyParameterValue.dateTime(4102444800000L))));
        check(FallbackAccess.eligible(1, descriptor, null, request), "TEE EC challenge eligible");
        check(!FallbackAccess.eligible(SecurityLevel.STRONGBOX, descriptor, null, request), "StrongBox untouched");
        check(!FallbackAccess.eligible(-1, descriptor, null, request), "unknown backend untouched");
        check(!FallbackAccess.eligible(1, descriptor, new KeyDescriptor(), request), "explicit signer untouched");
        descriptor.domain = Domain.SELINUX;
        check(!FallbackAccess.eligible(1, descriptor, null, request), "system namespace untouched");
        descriptor.domain = Domain.APP;
        descriptor.alias = "TrickyStoreTeeCheck";
        check(!FallbackAccess.eligible(1, descriptor, null, request), "probe untouched");
        descriptor.alias = "app-key";
        List<KeyParameter> noChallenge = new ArrayList<>(request);
        noChallenge.removeIf(p -> p.tag == Tag.ATTESTATION_CHALLENGE);
        check(!FallbackAccess.eligible(1, descriptor, null, noChallenge), "ordinary key untouched");
        List<KeyParameter> longChallenge = new ArrayList<>(noChallenge);
        longChallenge.add(p(Tag.ATTESTATION_CHALLENGE, KeyParameterValue.blob(new byte[129])));
        check(!FallbackAccess.eligible(1, descriptor, null, longChallenge), "oversized challenge untouched");
        List<KeyParameter> ed = new ArrayList<>(request);
        ed.removeIf(p -> p.tag == Tag.EC_CURVE);
        ed.add(p(Tag.EC_CURVE, KeyParameterValue.ecCurve(EcCurve.CURVE_25519)));
        check(!FallbackAccess.eligible(1, descriptor, null, ed), "Curve25519 untouched");
        List<KeyParameter> signer = new ArrayList<>(request);
        signer.add(p(Tag.PURPOSE, KeyParameterValue.keyPurpose(KeyPurpose.ATTEST_KEY)));
        check(!FallbackAccess.eligible(1, descriptor, null, signer), "attestation signing key untouched");
        List<KeyParameter> imports = FallbackAccess.imports(request);
        check(imports.stream().noneMatch(p -> p.tag == Tag.ATTESTATION_CHALLENGE
                || p.tag == Tag.ATTESTATION_ID_SERIAL || p.tag == Tag.ATTESTATION_ID_IMEI
                || p.tag == Tag.CERTIFICATE_NOT_BEFORE || p.tag == Tag.CERTIFICATE_NOT_AFTER),
                "import excludes attestation and certificate tags");
        check(imports.stream().anyMatch(p -> p.tag == Tag.PURPOSE)
                && imports.stream().anyMatch(p -> p.tag == Tag.EC_CURVE)
                && imports.stream().anyMatch(p -> p.tag == Tag.DIGEST), "import retains authorizations and curve");
        check(request.size() == 9, "request remains intact");
        CertificateGenerator.KeyGenParameters params = FallbackAccess.parameters(request);
        check(params.keySize == 256 && params.ecCurveName.equals("secp256r1")
                && params.attestationChallenge.length == 3, "translate EC request");
        List<KeyParameter> rsa = List.of(p(Tag.ALGORITHM, KeyParameterValue.algorithm(Algorithm.RSA)),
                p(Tag.KEY_SIZE, KeyParameterValue.integer(2048)),
                p(Tag.RSA_PUBLIC_EXPONENT, KeyParameterValue.longInteger(65537)),
                p(Tag.RSA_OAEP_MGF_DIGEST, KeyParameterValue.digest(2)),
                p(Tag.ATTESTATION_CHALLENGE, KeyParameterValue.blob(new byte[] {1})));
        params = FallbackAccess.parameters(rsa);
        check(params.keySize == 2048 && params.rsaPublicExponent.intValue() == 65537
                && params.rsaOaepMgfDigest.equals(List.of(2)), "translate RSA and MGF1 digest");
        android.content.pm.IPackageManager.packages = null;
        check(Arrays.equals(TrickyStoreService.resolveCallerPackages(), new String[] {"com.google.android.gms"}), "bound app when package lookup is empty");
        android.content.pm.IPackageManager.fail = true;
        check(TrickyStoreService.resolveCallerPackages().length == 1, "bound app when package lookup throws");
        android.app.ActivityThread.bound = null;
        check(TrickyStoreService.resolveCallerPackages() == null, "missing bound app stays unscoped");
        android.app.ActivityThread.bound = "com.google.android.gms";
        android.os.Process.isolated = true;
        check(TrickyStoreService.resolveCallerPackages() == null, "isolated process stays unscoped");
        android.os.Process.isolated = false;
        android.content.pm.IPackageManager.fail = false;
        android.content.pm.IPackageManager.packages = new String[] {"com.google.android.gms"};
        KeyPair root = KeyboxCheck.ecKeyPair();
        X509Certificate rootCert = KeyboxCheck.selfSigned(root, "CN=Root");
        android.provider.Settings.Secure.values.put(android.provider.Settings.Secure.KEYBOX_DATA,
                KeyboxCheck.keyboxXml(KeyboxCheck.pem("EC PRIVATE KEY", root.getPrivate().getEncoded()),
                        new X509Certificate[] {rootCert}, null, null));
        KeyStoreSecurityLevel backend = new KeyStoreSecurityLevel();
        KeyStore2 store = KeyStore2.getInstance();
        KeyMetadata result = recover(backend, descriptor, request, ErrorCode.SECURE_HW_COMMUNICATION_FAILED);
        check(result != null && result == store.metadata && result.key.domain == Domain.KEY_ID,
                "fallback returns persisted real key metadata");
        check(store.updated == result.key, "certificate stored under imported key ID");
        check(Arrays.equals(backend.supplied, new byte[backend.supplied.length]), "temporary private bytes cleared");
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate leaf = (X509Certificate)cf.generateCertificate(new java.io.ByteArrayInputStream(result.certificate));
        leaf.verify(root.getPublic());
        PrivateKey imported = KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(backend.keyCopy));
        java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA");
        signature.initSign(imported); signature.update(new byte[]{42}); byte[] sig = signature.sign();
        signature.initVerify(leaf.getPublicKey()); signature.update(new byte[]{42});
        check(signature.verify(sig), "imported private key matches certificate");
        check(leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") != null, "fallback carries attestation extension");
        com.android.internal.org.bouncycastle.asn1.ASN1Sequence description =
                com.android.internal.org.bouncycastle.asn1.ASN1Sequence.getInstance(
                    com.android.internal.org.bouncycastle.asn1.ASN1OctetString.getInstance(
                        leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")).getOctets());
        check(Arrays.equals(new byte[] {1,2,3},
                com.android.internal.org.bouncycastle.asn1.ASN1OctetString.getInstance(
                    description.getObjectAt(4)).getOctets()), "challenge survives request adapter");
        com.android.internal.org.bouncycastle.asn1.ASN1Sequence software =
                com.android.internal.org.bouncycastle.asn1.ASN1Sequence.getInstance(description.getObjectAt(6));
        boolean appId = false;
        for (int i = 0; i < software.size(); i++) {
            com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject tag =
                    com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject.getInstance(software.getObjectAt(i));
            if (tag.getTagNo() == 709) {
                byte[] id = com.android.internal.org.bouncycastle.asn1.ASN1OctetString
                        .getInstance(tag.getBaseObject()).getOctets();
                appId = com.android.internal.org.bouncycastle.asn1.ASN1Sequence.getInstance(id).size() == 2;
            }
        }
        check(appId, "application ID is wrapped exactly once");
        check(recover(backend, descriptor, request, -1) == null, "unrelated hardware error preserved");
        android.content.pm.IPackageManager.packages = new String[] {"example.untargeted"};
        check(recover(backend, descriptor, request, ErrorCode.SECURE_HW_COMMUNICATION_FAILED) == null,
                "untargeted package keeps original failure");
        android.content.pm.IPackageManager.packages = new String[] {"com.google.android.gms"};
        store.failUpdate = true;
        check(recover(backend, descriptor, request, ErrorCode.SECURE_HW_COMMUNICATION_FAILED) == null
                && store.deleted, "failed certificate persistence removes imported key");
        store.failUpdate = false; store.deleted = false; store.failRead = true;
        check(recover(backend, descriptor, request, ErrorCode.ATTESTATION_KEYS_NOT_PROVISIONED) == null
                && store.deleted, "failed metadata read removes imported key");
        store.failRead = false;
        android.provider.Settings.Secure.values.put(android.provider.Settings.Secure.TRICKY_STORE_TARGET,
                "com.google.android.gms?");
        android.os.SystemClock.now += 5000;
        check(recover(backend, descriptor, request, ErrorCode.SECURE_HW_COMMUNICATION_FAILED) == null,
                "leaf-only policy never imports software keys");
    }
}
