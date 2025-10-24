import 'dart:ffi' as ffi;
import 'tufkey.dart';
void main() {
  final t = TufkeyFFI.load(overridePath: r'/Users/adilsebbary/hardlock-snc/lib/libhardlock_snc.dylib');
  final s = t.newSession();
  final msg = 'hello_tufkey'.codeUnits;
  final ct = t.encrypt(s, msg);
  final pt = t.decrypt(s, ct);
  print(String.fromCharCodes(pt));
  t.free(s);
}
