import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

/**
 * 서명 다이제스트가 알고리즘 이름을 따르는지 확인한다.
 *
 * <p>회귀 방지용이다. 예전 구현은 알고리즘 이름과 무관하게 항상 SHA-256으로
 * 다이제스트했다. 그러면 SHA384withECDSA로 만든 인증서는 SignatureAlgorithm
 * OID가 SHA-384인데 실제 서명 바이트는 SHA-256 해시에 대한 것이 되어, 어떤
 * 검증자도 받아들이지 않는다. 기존 테스트가 SHA-256만 써서 이 결함을 놓쳤다.
 */
public class DigestCheck {
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
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));
        KeyPair ec = g.generateKeyPair();
        byte[] data = "attestation tbs".getBytes();

        for (String alg : new String[] {"SHA256withECDSA", "SHA384withECDSA",
                "SHA512withECDSA"}) {
            byte[] sig = sign(alg, ec, data);
            check(BcCryptoShim.verify(alg, ec.getPublic(), data, sig),
                    alg + " signature verifies with its own digest");
            String other = alg.equals("SHA256withECDSA") ? "SHA384withECDSA"
                    : alg.equals("SHA384withECDSA") ? "SHA512withECDSA" : "SHA256withECDSA";
            check(!BcCryptoShim.verify(other, ec.getPublic(), data, sig),
                    alg + " signature does not verify as " + other);
        }

        KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA");
        rg.initialize(3072);
        KeyPair rsa = rg.generateKeyPair();
        for (String alg : new String[] {"SHA256withRSA", "SHA384withRSA",
                "SHA512withRSA"}) {
            byte[] sig = sign(alg, rsa, data);
            check(BcCryptoShim.verify(alg, rsa.getPublic(), data, sig),
                    alg + " signature verifies with its own digest");
        }

        // 서명 바이트가 정말 해당 다이제스트에 대한 것인지 독립적으로 확인한다.
        byte[] sig = sign("SHA384withECDSA", ec, data);
        byte[] sha384 = MessageDigest.getInstance("SHA-384").digest(data);
        byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(data);
        var seq = com.android.internal.org.bouncycastle.asn1.ASN1Sequence
                .getInstance(sig);
        BigInteger r = com.android.internal.org.bouncycastle.asn1.ASN1Integer
                .getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = com.android.internal.org.bouncycastle.asn1.ASN1Integer
                .getInstance(seq.getObjectAt(1)).getValue();
        var pub = (com.android.internal.org.bouncycastle.crypto.params.ECPublicKeyParameters)
                com.android.internal.org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
                        .generatePublicKeyParameter(ec.getPublic());
        check(rawVerify(pub, sha384, r, s),
                "SHA384withECDSA signature is over the SHA-384 hash");
        check(!rawVerify(pub, sha256, r, s),
                "SHA384withECDSA signature is not over the SHA-256 hash");

        System.out.println();
        System.out.println(failures == 0 ? "ALL CHECKS PASSED" : failures + " FAILURE(S)");
        if (failures != 0) System.exit(1);
    }

    static byte[] sign(String alg, KeyPair kp, byte[] data) throws Exception {
        var signer = BcCryptoShim.newSigner(alg, kp.getPrivate());
        var out = signer.getOutputStream();
        out.write(data);
        out.close();
        return signer.getSignature();
    }

    static boolean rawVerify(com.android.internal.org.bouncycastle.crypto.params
            .ECPublicKeyParameters pub, byte[] hash, BigInteger r, BigInteger s) {
        var v = new com.android.internal.org.bouncycastle.crypto.signers.ECDSASigner();
        v.init(false, pub);
        return v.verifySignature(hash, r, s);
    }
}
