package android.security;
import android.system.keystore2.*;
public class KeyStore2 {
 private static final KeyStore2 instance = new KeyStore2();
 public KeyMetadata metadata;
 public boolean failUpdate, failRead, deleted;
 public KeyDescriptor updated;
 public static KeyStore2 getInstance() { return instance; }
 public void updateSubcomponents(KeyDescriptor key, byte[] leaf, byte[] ca) throws KeyStoreException {
  if (failUpdate) throw new KeyStoreException(4, "update failed");
  updated = key; metadata.certificate = leaf; metadata.certificateChain = ca;
 }
 public KeyEntryResponse getKeyEntry(KeyDescriptor key) throws KeyStoreException {
  if (failRead) throw new KeyStoreException(4, "read failed");
  KeyEntryResponse entry = new KeyEntryResponse(); entry.metadata = metadata; return entry;
 }
 public void deleteKey(KeyDescriptor key) throws KeyStoreException { deleted = true; }
}
