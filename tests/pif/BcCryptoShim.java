/**
 * Host-only accessor: {@code BcCrypto} is package private in the framework.
 *
 * <p>The checks run in the default package so they stay easy to invoke by name;
 * this shim forwards to the adapter compiled alongside them.
 */
public final class BcCryptoShim {
    private BcCryptoShim() {}

    public static com.android.internal.org.bouncycastle.operator.ContentSigner newSigner(
            String algorithm, java.security.PrivateKey key) throws Exception {
        return android.security.trickystore.BcCryptoAccess.newSigner(algorithm, key);
    }

    public static boolean verify(String algorithm, java.security.PublicKey key,
            byte[] data, byte[] signature) throws Exception {
        return android.security.trickystore.BcCryptoAccess.verify(
                algorithm, key, data, signature);
    }
}
