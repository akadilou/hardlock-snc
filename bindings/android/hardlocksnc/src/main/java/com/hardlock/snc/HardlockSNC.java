package com.hardlock.snc;
public final class HardlockSNC {
  static { System.loadLibrary("hardlock_snc"); }
  public static native int hardlock_consts_header_len();
  public static native int hardlock_consts_nonce_len();
}
