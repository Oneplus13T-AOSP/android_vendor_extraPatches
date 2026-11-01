package android.util;
public final class Log {
  public static final int VERBOSE=2, DEBUG=3, INFO=4, WARN=5, ERROR=6;
  private static String f(String lvl,String t,String m){ return "["+lvl+"/"+t+"] "+m; }
  public static int v(String t, String m){ return 0; }
  public static int d(String t, String m){ return 0; }
  public static int i(String t, String m){ System.out.println(f("I",t,m)); return 0; }
  public static int w(String t, String m){ System.out.println(f("W",t,m)); return 0; }
  public static int e(String t, String m){ System.out.println(f("E",t,m)); return 0; }
  public static int e(String t, String m, Throwable e){ System.out.println(f("E",t,m)); e.printStackTrace(System.out); return 0; }
  public static int w(String t, String m, Throwable e){ System.out.println(f("W",t,m)); e.printStackTrace(System.out); return 0; }
  public static int w(String t, Throwable e){ return w(t, String.valueOf(e), e); }
  public static boolean isLoggable(String t, int l){ return false; }
}
