package android.content;
public class Context {
    private final ContentResolver resolver = new ContentResolver();
    public android.content.pm.PackageManager getPackageManager() { return new android.content.pm.PackageManager(); }
    public ContentResolver getContentResolver() { return resolver; }
}
