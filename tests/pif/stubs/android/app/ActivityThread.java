package android.app;
public class ActivityThread {
    private static final ActivityThread thread = new ActivityThread();
    private static final android.content.Context context = new android.content.Context();
    public static String bound = "com.google.android.gms";
    public static android.content.pm.IPackageManager getPackageManager() { return new android.content.pm.IPackageManager(); }
    public static String currentPackageName() { return bound; }
    public static ActivityThread currentActivityThread() { return thread; }
    public static android.content.Context currentApplication() { return context; }
    public android.content.Context getSystemContext() { return context; }
}
