package android.provider;
public final class Settings {
    public static final class Secure {
        public static final String TRICKY_STORE_TARGET = "targets";
        public static final String KEYBOX_DATA = "keybox";
        public static final java.util.Map<String, String> values = new java.util.HashMap<>();
        public static boolean failReads;
        public static String getString(android.content.ContentResolver resolver, String key) {
            if (failReads) throw new IllegalStateException("provider unavailable");
            return values.get(key);
        }
    }
}
