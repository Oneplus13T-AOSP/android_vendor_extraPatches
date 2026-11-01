package android.hardware.security.keymint;
public class KeyParameterValue {
 private long number; private byte[] bytes;
 private static KeyParameterValue n(long n) { KeyParameterValue v = new KeyParameterValue(); v.number = n; return v; }
 public static KeyParameterValue algorithm(int n) { return n(n); }
 public static KeyParameterValue ecCurve(int n) { return n(n); }
 public static KeyParameterValue keyPurpose(int n) { return n(n); }
 public static KeyParameterValue integer(int n) { return n(n); }
 public static KeyParameterValue digest(int n) { return n(n); }
 public static KeyParameterValue paddingMode(int n) { return n(n); }
 public static KeyParameterValue longInteger(long n) { return n(n); }
 public static KeyParameterValue dateTime(long n) { return n(n); }
 public static KeyParameterValue boolValue(boolean n) { return n(n ? 1 : 0); }
 public static KeyParameterValue blob(byte[] b) { KeyParameterValue v = n(0); v.bytes = b; return v; }
 public int getAlgorithm() { return (int)number; }
 public int getEcCurve() { return (int)number; }
 public int getKeyPurpose() { return (int)number; }
 public int getInteger() { return (int)number; }
 public int getDigest() { return (int)number; }
 public int getPaddingMode() { return (int)number; }
 public long getLongInteger() { return number; }
 public long getDateTime() { return number; }
 public byte[] getBlob() { return bytes; }
}
