package android.security.trickystore;
/**
 * Host stub: the real AttestationUtils reads system properties and boot images.
 *
 * <p>Keeps the zero-detection helpers real, because the leaf rewriter's RootOfTrust
 * handling depends on them and that logic is under test.
 */
public final class AttestationUtils {
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte value : bytes) hex.append(String.format("%02x", value & 0xff));
        return hex.toString();
    }

    public static boolean isNullOrZeroBootKey(byte[] key) {
        if (key == null) return true;
        for (byte value : key) {
            if (value != 0) return false;
        }
        return true;
    }

    public static boolean isNullOrZeroBootHash(byte[] hash) {
        return isNullOrZeroBootKey(hash);
    }

    public static byte[] getBootKey() { return new byte[32]; }
    public static byte[] getBootHash() { return new byte[32]; }
    public static int[] getPatchLevels(String[] p) { return new int[] {202610, 20261001, 20261001}; }
    public static int getOsVersion() { return 170000; }
    public static int getAttestVersion() { return 300; }
    public static int getKeymasterVersion() { return 300; }
    public static void invalidateFallbackBootState() {}
}
