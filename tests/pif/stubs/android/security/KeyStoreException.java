package android.security;
public class KeyStoreException extends Exception {
 private final int code;
 public KeyStoreException(int code, String message) { super(message); this.code = code; }
 public int getErrorCode() { return code; }
}
