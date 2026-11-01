package android.security;
import android.hardware.security.keymint.KeyParameter;
import android.system.keystore2.*;
public class KeyStoreSecurityLevel {
 public byte[] supplied, keyCopy;
 public java.util.Collection<KeyParameter> arguments;
 public KeyMetadata importKey(KeyDescriptor descriptor, KeyDescriptor signer,
   java.util.Collection<KeyParameter> args, int flags, byte[] key) throws KeyStoreException {
  supplied = key; keyCopy = key.clone(); arguments = args;
  KeyMetadata metadata = new KeyMetadata(); metadata.key = new KeyDescriptor();
  metadata.key.domain = Domain.KEY_ID; metadata.key.nspace = 99;
  KeyStore2.getInstance().metadata = metadata; return metadata;
 }
}
