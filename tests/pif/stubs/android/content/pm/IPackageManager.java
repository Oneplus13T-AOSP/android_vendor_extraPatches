package android.content.pm;
public class IPackageManager {
 public static String[] packages = {"com.google.android.gms"};
 public static boolean fail;
 public String[] getPackagesForUid(int uid) throws Exception {
  if (fail) throw new Exception("provider failure");
  return packages;
 }
}
