package android.content.pm;
public class PackageManager {
 public static final int GET_SIGNATURES = 64;
 public String[] getPackagesForUid(int uid) { return IPackageManager.packages; }
 public PackageInfo getPackageInfo(String name, int flags) { return new PackageInfo(); }
}
