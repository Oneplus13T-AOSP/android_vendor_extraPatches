package android.security.pif;
public class PlayIntegrityProfile {
 public static boolean isSpoofedPackage(String[] p) {
  return p != null && java.util.Arrays.asList(p).contains("com.google.android.gms");
 }
 public static java.util.Map<String, String> getIdentity() { return java.util.Map.of("BRAND", "google"); }
 public static byte[] identityBytes(java.util.Map<String, String> identity, String field) {
  return (identity == null ? "test" : identity.getOrDefault(field, "test")).getBytes(java.nio.charset.StandardCharsets.UTF_8);
 }
}
