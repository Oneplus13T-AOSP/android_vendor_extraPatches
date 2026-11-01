package android.security.trickystore;
/** Host stub: only the invalidation hook is reachable from KeyBoxManager. */
public final class AttestationUtils {
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte value : bytes) hex.append(String.format("%02x", value & 0xff));
        return hex.toString();
    }
    public static byte[] getBootKey() { return new byte[32]; }
    public static byte[] getBootHash() { return new byte[32]; }
    public static int[] getPatchLevels(String[] p) { return new int[] {202610,20261001,20261001}; }
    public static int getOsVersion() { return 170000; }
    public static int getAttestVersion() { return 400; }
    public static int getKeymasterVersion() { return 400; }
    public static void invalidateFallbackBootState() {}
}
