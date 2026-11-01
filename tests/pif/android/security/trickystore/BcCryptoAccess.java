package android.security.trickystore;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Host-only bridge into {@link BcCrypto}.
 *
 * <p>{@code BcCrypto} is package private on purpose: it is an implementation detail
 * of the attestation code and must not become part of the framework surface. The
 * checks live in the default package, so they reach it through this thin adapter,
 * which is compiled only by the host test run and never installed.
 */
public final class BcCryptoAccess {
    private BcCryptoAccess() {}

    public static com.android.internal.org.bouncycastle.operator.ContentSigner newSigner(
            String algorithm, PrivateKey key) throws Exception {
        return BcCrypto.newSigner(algorithm, key);
    }

    public static boolean verify(String algorithm, PublicKey key, byte[] data, byte[] signature)
            throws Exception {
        return BcCrypto.verify(algorithm, key, data, signature);
    }
}
