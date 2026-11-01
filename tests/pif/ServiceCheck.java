import android.os.SystemClock;
import android.provider.Settings.Secure;
import android.security.trickystore.TrickyStoreService;

/** Checks the production policy and refresh code with a controllable provider/clock. */
public class ServiceCheck {
    private static void check(boolean condition, String name) {
        if (!condition) throw new AssertionError(name);
        System.out.println("ok: " + name);
    }
    private static String[] pkg(String value) { return new String[] {value}; }
    public static void main(String[] args) {
        TrickyStoreService service = TrickyStoreService.getInstance();
        check(service.needHack(123, pkg("com.google.android.gms")), "GMS default");
        check(service.needHack(123, pkg("com.android.vending")), "Play Store default");
        for (String p : new String[] {"android", "com.google.android.gsf",
                "com.revolut.revolut", "io.github.vvb2060.keyattestation", "example.app"}) {
            check(!service.needHack(123, pkg(p)) && !service.needGenerate(123, pkg(p)),
                    "native default for " + p);
        }
        check(service.needSoftwareFallback(123, pkg("com.google.android.gms")), "AUTO permits fallback");
        Secure.values.put(Secure.TRICKY_STORE_TARGET,
                "example.app!\ncom.google.android.gms-\nexample.reader?");
        SystemClock.now += 5000;
        check(service.needGenerate(123, pkg("example.app")), "explicit generation target");
        check(!service.needHack(123, pkg("com.google.android.gms")), "explicit skip target");
        check(service.needHack(123, pkg("example.reader")), "explicit leaf target");
        check(!service.needSoftwareFallback(123, pkg("example.reader")), "leaf-only denies fallback");
        check(service.needSoftwareFallback(123, pkg("example.app")), "generate permits fallback");
        Secure.values.remove(Secure.TRICKY_STORE_TARGET);
        SystemClock.now += 5000;
        check(service.needHack(123, pkg("com.google.android.gms"))
                && !service.needGenerate(123, pkg("example.app")), "target reset");
    }
}
