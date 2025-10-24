import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'package:ffi/ffi.dart';

typedef _snc_new_c = ffi.Pointer<ffi.Void> Function();
typedef _snc_free_c = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _snc_encrypt_c = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>, ffi.Uint64,
  ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint64>);
typedef _snc_decrypt_c = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>, ffi.Uint64,
  ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint64>);

typedef _snc_new_d = ffi.Pointer<ffi.Void> Function();
typedef _snc_free_d = void Function(ffi.Pointer<ffi.Void>);
typedef _snc_encrypt_d = int Function(
  ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint64>);
typedef _snc_decrypt_d = int Function(
  ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint64>);

class TufkeyFFI {
  late final ffi.DynamicLibrary _lib;
  late final _snc_new_d _new;
  late final _snc_free_d _free;
  late final _snc_encrypt_d _enc;
  late final _snc_decrypt_d _dec;

  TufkeyFFI._();

  static TufkeyFFI load({String? overridePath}) {
    final s = TufkeyFFI._();
    if (overridePath != null) {
      s._lib = ffi.DynamicLibrary.open(overridePath);
    } else if (Platform.isAndroid) {
      s._lib = ffi.DynamicLibrary.open('libhardlock_snc.so');
    } else if (Platform.isMacOS) {
      s._lib = ffi.DynamicLibrary.open('libhardlock_snc.dylib');
    } else if (Platform.isLinux) {
      s._lib = ffi.DynamicLibrary.open('libhardlock_snc.so');
    } else if (Platform.isWindows) {
      s._lib = ffi.DynamicLibrary.open('hardlock_snc.dll');
    } else {
      throw UnsupportedError('Unsupported platform');
    }

    ffi.Pointer<T> _sym<T extends ffi.NativeType>(String name) =>
        s._lib.lookup<T>(name);

    s._new = _sym<ffi.NativeFunction<_snc_new_c>>('hl_snc_session_new_initiator')
        .asFunction<_snc_new_d>();
    s._free = _sym<ffi.NativeFunction<_snc_free_c>>('hl_snc_session_free')
        .asFunction<_snc_free_d>();
    s._enc = _sym<ffi.NativeFunction<_snc_encrypt_c>>('hl_snc_encrypt')
        .asFunction<_snc_encrypt_d>();
    s._dec = _sym<ffi.NativeFunction<_snc_decrypt_c>>('hl_snc_decrypt')
        .asFunction<_snc_decrypt_d>();
    return s;
  }

  ffi.Pointer<ffi.Void> newSession() => _new();
  void free(ffi.Pointer<ffi.Void> h) => _free(h);

  List<int> encrypt(ffi.Pointer<ffi.Void> h, List<int> plain) {
    final inPtr = calloc<ffi.Uint8>(plain.length);
    for (var i = 0; i < plain.length; i++) inPtr[i] = plain[i];
    final out = calloc<ffi.Uint8>(plain.length + 64);
    final outLen = calloc<ffi.Uint64>();
    final rc = _enc(h, inPtr, plain.length, out, outLen);
    calloc.free(inPtr);
    if (rc != 0) { calloc.free(out); calloc.free(outLen); throw Exception('enc rc=$rc'); }
    final ct = out.asTypedList(outLen.value);
    final ret = List<int>.from(ct);
    calloc.free(out); calloc.free(outLen);
    return ret;
  }

  List<int> decrypt(ffi.Pointer<ffi.Void> h, List<int> ct) {
    final inPtr = calloc<ffi.Uint8>(ct.length);
    for (var i = 0; i < ct.length; i++) inPtr[i] = ct[i];
    final out = calloc<ffi.Uint8>(ct.length + 64);
    final outLen = calloc<ffi.Uint64>();
    final rc = _dec(h, inPtr, ct.length, out, outLen);
    calloc.free(inPtr);
    if (rc != 0) { calloc.free(out); calloc.free(outLen); throw Exception('dec rc=$rc'); }
    final pt = out.asTypedList(outLen.value);
    final ret = List<int>.from(pt);
    calloc.free(out); calloc.free(outLen);
    return ret;
  }
}
