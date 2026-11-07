package android.security.pif;
/**
 * Host stub for the profile reader: the real one reads Settings.Secure and compares
 * against the process Build, neither of which exists on the host.
 *
 * <p>Mirrors the production contract that matters to callers: {@link #identityBytes}
 * returns null for a field the profile does not carry, instead of falling back to the
 * device Build.
 */
public class PlayIntegrityProfile {
    /** Identity the stub hands out; tests may replace it. */
    public static java.util.Map<String, String> identity = new java.util.LinkedHashMap<>(
            java.util.Map.of("BRAND", "google", "DEVICE", "bluejay",
                    "PRODUCT", "bluejay_beta", "MANUFACTURER", "Google",
                    "MODEL", "Pixel 6a"));

    public static boolean isSpoofedPackage(String[] p) {
        return p != null && java.util.Arrays.asList(p).contains("com.google.android.gms");
    }

    public static java.util.Map<String, String> getIdentity() {
        return identity == null || identity.isEmpty() ? null : identity;
    }

    public static byte[] identityBytes(java.util.Map<String, String> identity, String field) {
        String value = identity == null ? null : identity.get(field);
        return value == null || value.isEmpty()
                ? null
                : value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    public static String describeIdentity(java.util.Map<String, String> identity) {
        if (identity == null) return "none";
        StringBuilder sb = new StringBuilder();
        for (String field : new String[] {"BRAND", "DEVICE", "PRODUCT", "MANUFACTURER", "MODEL"}) {
            String value = identity.get(field);
            if (value == null || value.isEmpty()) continue;
            if (sb.length() > 0) sb.append(' ');
            sb.append(field).append('=').append(value);
        }
        return sb.length() == 0 ? "none" : sb.toString();
    }
}
