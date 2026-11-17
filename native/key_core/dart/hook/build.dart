import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

/// Builds the key core — the crate one directory up, `native/key_core` — for
/// the target the Dart or Flutter build asks for, and hands the library over
/// as a bundled code asset (`package:key_core/key_core.dart`).
///
/// **Nothing is fetched.** Cargo runs `--offline --locked`, so every crate
/// comes from `~/.cargo/registry` exactly as `Cargo.lock` pins it, and rustup
/// installs no toolchain or target that `rust-toolchain.toml` names but this
/// machine lacks (`RUSTUP_AUTO_INSTALL=0`): a missing piece fails the build
/// and says so, rather than arriving unannounced. That is the lesson
/// `docs/BITCOIN_PRIVACY_DESIGN.md#m6-plan` records from PayJoin's builder.
///
/// **Android** links with the NDK the build passes in `cCompiler`, through its
/// clang wrapper for the API level the build passes (the app's `minSdk`), with
/// 16 KiB pages: the same as `tool/build_android.sh`, whose output
/// `tool/check_android.sh` reads back. That NDK must be [ndkRevision]: Flutter
/// does not pass `flutter.ndkVersion` here but the NDK its `android-ndk`
/// setting or `ANDROID_NDK_HOME` names, or else the newest one installed.
///
/// **iOS** is built for the iPhone and for the simulator on an Apple silicon
/// Mac, at the deployment target the build passes (Flutter passes 13); the C
/// compiler and the SDK come from Xcode through `xcrun`, as on macOS.
///
/// **Anything else is refused** by name, the Intel iOS simulator included.
void main(List<String> arguments) async {
  await build(arguments, buildKeyCore);
}

/// Flutter 3.44.8's `flutter.ndkVersion`, which android/app/build.gradle.kts
/// uses and `tool/android_env.sh` pins.
const String ndkRevision = '28.2.13676358';

/// The `Pkg.Revision` of the NDK whose `toolchains/llvm/prebuilt/<host>/bin`
/// is [ndkBin], or null when its `source.properties` names none.
String? ndkRevisionAt(Uri ndkBin) {
  final properties =
      File.fromUri(ndkBin.resolve('../../../../../source.properties'));
  if (!properties.existsSync()) return null;
  for (final line in properties.readAsLinesSync()) {
    final match = RegExp(r'^\s*Pkg\.Revision\s*=\s*(\S+)\s*$').firstMatch(line);
    if (match != null) return match.group(1);
  }
  return null;
}

/// Refuses an NDK other than [ndkRevision]: another one links a library
/// nobody has read back.
void requireNdk(Uri ndkBin) {
  final revision = ndkRevisionAt(ndkBin);
  if (revision != ndkRevision) {
    throw BuildError(
      message: 'The key core is built with NDK $ndkRevision; the build '
          'passed ${revision == null ? 'an NDK of unknown revision' : 'NDK '
              '$revision'} at ${ndkBin.toFilePath()}. Set ANDROID_NDK_HOME '
          'to NDK $ndkRevision.',
    );
  }
}

/// The Rust triple, and for Android the NDK's clang prefix, of a target.
/// For iOS, [iOSSdk] tells an iPhone from the simulator.
({String triple, String? ndkClang})? rustTarget(OS os, Architecture arch,
        [IOSSdk? iOSSdk]) =>
    switch ((os, arch)) {
      (OS.android, Architecture.arm64) => (
          triple: 'aarch64-linux-android',
          ndkClang: 'aarch64-linux-android',
        ),
      (OS.android, Architecture.arm) => (
          triple: 'armv7-linux-androideabi',
          ndkClang: 'armv7a-linux-androideabi',
        ),
      (OS.android, Architecture.x64) => (
          triple: 'x86_64-linux-android',
          ndkClang: 'x86_64-linux-android',
        ),
      (OS.macOS, Architecture.arm64) => (
          triple: 'aarch64-apple-darwin',
          ndkClang: null,
        ),
      (OS.iOS, Architecture.arm64) when iOSSdk == IOSSdk.iPhoneOS => (
          triple: 'aarch64-apple-ios',
          ndkClang: null,
        ),
      (OS.iOS, Architecture.arm64) when iOSSdk == IOSSdk.iPhoneSimulator => (
          triple: 'aarch64-apple-ios-sim',
          ndkClang: null,
        ),
      _ => null,
    };

/// Cargo's arguments: release, offline, locked, one target, one target
/// directory.
List<String> cargoArguments({
  required String triple,
  required Uri manifest,
  required Uri targetDirectory,
}) =>
    [
      'build',
      '--release',
      '--offline',
      '--locked',
      '--target',
      triple,
      '--manifest-path',
      manifest.toFilePath(),
      '--target-dir',
      targetDirectory.toFilePath(),
    ];

/// The environment Cargo and the `cc` crate read, on top of the build's own.
///
/// For Android, [ndkBin] is the directory of the compiler the build passed;
/// the linker and libsecp256k1's C compiler are its clang wrapper for [api].
Map<String, String> cargoEnvironment({
  required String triple,
  String? ndkClang,
  Uri? ndkBin,
  int? api,
  int? macOSVersion,
  int? iOSVersion,
}) {
  final environment = <String, String>{
    'RUSTUP_AUTO_INSTALL': '0',
    'CARGO_NET_OFFLINE': 'true',
  };
  if (ndkClang != null) {
    final clang = ndkBin!.resolve('$ndkClang$api-clang').toFilePath();
    final upper = triple.toUpperCase().replaceAll('-', '_');
    final lower = triple.replaceAll('-', '_');
    environment
      ..['CARGO_TARGET_${upper}_LINKER'] = clang
      ..['CARGO_TARGET_${upper}_RUSTFLAGS'] =
          '-C link-arg=-Wl,-z,max-page-size=16384'
      ..['CC_$lower'] = clang
      ..['AR_$lower'] = ndkBin.resolve('llvm-ar').toFilePath();
  }
  if (triple.contains('-apple-')) {
    // **Apple's linker strips, not rustc.** `strip = "symbols"` left the
    // simulator library's string table at an offset 4 bytes off the 8 that
    // Xcode 27.1's `ld` requires of a library linked against ("mis-aligned
    // LINKEDIT string pool"); `-x -S` at link time drops the same local and
    // debug symbols, to the same size, and keeps it aligned.
    final upper = triple.toUpperCase().replaceAll('-', '_');
    environment
      ..['CARGO_PROFILE_RELEASE_STRIP'] = 'none'
      ..['CARGO_TARGET_${upper}_RUSTFLAGS'] =
          '-C link-arg=-Wl,-x -C link-arg=-Wl,-S';
  }
  if (macOSVersion != null) {
    environment['MACOSX_DEPLOYMENT_TARGET'] = '$macOSVersion.0';
  }
  if (iOSVersion != null) {
    environment['IPHONEOS_DEPLOYMENT_TARGET'] = '$iOSVersion.0';
  }
  return environment;
}

Future<void> buildKeyCore(BuildInput input, BuildOutputBuilder output) async {
  if (!input.config.buildCodeAssets) return;
  final code = input.config.code;
  final iOSSdk = code.targetOS == OS.iOS ? code.iOS.targetSdk : null;
  final target =
      rustTarget(code.targetOS, code.targetArchitecture, iOSSdk);
  if (target == null) {
    throw BuildError(
      message: 'The key core is not built for ${code.targetOS} '
          '${code.targetArchitecture}${iOSSdk == null ? '' : ' $iOSSdk'} '
          '(docs/RUST_KEY_CORE_DESIGN.md#phase-1).',
    );
  }
  if (code.linkModePreference == LinkModePreference.static) {
    throw BuildError(message: 'The key core is built as a dynamic library only.');
  }

  final crate = input.packageRoot.resolve('../');
  Uri? ndkBin;
  int? api;
  if (target.ndkClang != null) {
    final compiler = code.cCompiler?.compiler;
    if (compiler == null) {
      throw BuildError(
          message: 'An Android build of the key core needs the NDK the build '
              'passes as its C compiler, and none was passed.');
    }
    ndkBin = compiler.resolve('./');
    requireNdk(ndkBin);
    api = code.android.targetNdkApi;
    final wrapper = File.fromUri(ndkBin.resolve('${target.ndkClang}$api-clang'));
    if (!wrapper.existsSync()) {
      throw BuildError(message: 'No NDK clang for API $api: ${wrapper.path}');
    }
  }

  final targetDirectory = input.outputDirectoryShared.resolve('cargo/');
  final arguments = cargoArguments(
    triple: target.triple,
    manifest: crate.resolve('Cargo.toml'),
    targetDirectory: targetDirectory,
  );
  final environment = cargoEnvironment(
    triple: target.triple,
    ndkClang: target.ndkClang,
    ndkBin: ndkBin,
    api: api,
    macOSVersion:
        code.targetOS == OS.macOS ? code.macOS.targetVersion : null,
    iOSVersion: code.targetOS == OS.iOS ? code.iOS.targetVersion : null,
  );
  final result = await Process.run(
    _cargo(),
    arguments,
    // The crate's own directory, so rustup reads its rust-toolchain.toml and
    // Cargo its .cargo/config.toml (curve25519-dalek's backend, O14).
    workingDirectory: crate.toFilePath(),
    environment: environment,
  );
  if (result.exitCode != 0) {
    throw BuildError(
      message: 'cargo ${arguments.join(' ')} exited ${result.exitCode}:\n'
          '${result.stderr}',
    );
  }

  final name =
      code.targetOS == OS.android ? 'libkey_core.so' : 'libkey_core.dylib';
  final built = File.fromUri(
      targetDirectory.resolve('${target.triple}/release/$name'));
  final bundled = input.outputDirectory.resolve(name);
  await built.copy(bundled.toFilePath());
  output.assets.code.add(CodeAsset(
    package: input.packageName,
    name: 'key_core.dart',
    linkMode: DynamicLoadingBundled(),
    file: bundled,
  ));

  // What makes the library different: the crate's sources and pins.
  final sources = Directory.fromUri(crate.resolve('src/'))
      .listSync()
      .whereType<File>()
      .where((f) => f.path.endsWith('.rs'))
      .map((f) => f.uri);
  output.dependencies.addAll([
    ...sources,
    crate.resolve('Cargo.toml'),
    crate.resolve('Cargo.lock'),
    crate.resolve('rust-toolchain.toml'),
    crate.resolve('.cargo/config.toml'),
  ]);
}

/// rustup's `cargo`, found where rustup puts it when a build's PATH does not
/// reach `~/.cargo/bin` (an IDE's, say).
String _cargo() {
  final home = Platform.environment['HOME'];
  final installed = home == null ? null : File('$home/.cargo/bin/cargo');
  return installed != null && installed.existsSync() ? installed.path : 'cargo';
}
