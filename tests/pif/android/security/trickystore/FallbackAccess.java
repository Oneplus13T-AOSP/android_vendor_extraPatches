package android.security.trickystore;
import android.hardware.security.keymint.KeyParameter;
import android.system.keystore2.KeyDescriptor;
public class FallbackAccess {
 public static boolean eligible(int l, KeyDescriptor d, KeyDescriptor s, java.util.Collection<KeyParameter> a) {
  return KeyboxGenerationFallback.eligible(l,d,s,a);
 }
 public static java.util.List<KeyParameter> imports(java.util.Collection<KeyParameter> a) {
  return KeyboxGenerationFallback.importArguments(a);
 }
 public static CertificateGenerator.KeyGenParameters parameters(java.util.Collection<KeyParameter> a) {
  return KeyboxGenerationFallback.parameters(a);
 }
}
