package android.app;
public class AppGlobals {
    public static android.content.Context getInitialApplication() {
        return ActivityThread.currentApplication();
    }
}
