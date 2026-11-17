import 'dart:io';
import 'dart:typed_data';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart'
    show BuildError, BuildInputBuilder, BuildOutputBuilder;
import 'package:test/test.dart';

import '../hook/build.dart' as hook;

/// The build hook, run as Flutter runs it for an Android build — the NDK as
/// its C compiler (clang, ld.lld and llvm-ar from one `bin`, as
/// `AndroidSdk.getNdkClangPath` and its siblings hand them over) and the app's
/// API level — but through `testCodeBuildHook` rather than Flutter, which
/// this Mac cannot run without Xcode and a JDK. Each test is a real Cargo
/// build of the crate, offline.
///
/// The host build is the other half: `key_core_oracle_test.dart` loads the
/// library `dart test` had this hook build and bundle.
void main() {
  final home = Platform.environment['HOME']!;
  final bin = Uri.directory(
      '$home/Library/Android/sdk/ndk/${hook.ndkRevision}/toolchains/llvm/'
      'prebuilt/darwin-x86_64/bin/');
  final asFlutterPassesIt = CCompilerConfig(
    compiler: bin.resolve('clang'),
    linker: bin.resolve('ld.lld'),
    archiver: bin.resolve('llvm-ar'),
  );

  group('an Android build', () {
    // ELF e_machine: AArch64 183, ARM 40, x86-64 62.
    for (final (architecture, machine) in [
      (Architecture.arm64, 183),
      (Architecture.arm, 40),
      (Architecture.x64, 62),
    ]) {
      test('for $architecture bundles one library, 16 KiB-aligned', () async {
        await testCodeBuildHook(
          mainMethod: hook.main,
          targetOS: OS.android,
          targetArchitecture: architecture,
          targetAndroidNdkApi: 30,
          cCompiler: asFlutterPassesIt,
          check: (input, output) {
            final assets = output.assets.code;
            expect(assets, hasLength(1));
            final asset = assets.single;
            expect(asset.id, 'package:key_core/key_core.dart');
            expect(asset.linkMode, DynamicLoadingBundled());
            final elf = _Elf(File.fromUri(asset.file!).readAsBytesSync());
            expect(elf.machine, machine);
            expect(elf.loadAlignments, isNotEmpty);
            expect(elf.loadAlignments, everyElement(greaterThanOrEqualTo(16384)));
            final crate = input.packageRoot.resolve('../');
            expect(output.dependencies, containsAll([
              crate.resolve('Cargo.lock'),
              crate.resolve('Cargo.toml'),
              crate.resolve('rust-toolchain.toml'),
              crate.resolve('.cargo/config.toml'),
              crate.resolve('src/lib.rs'),
              crate.resolve('src/keys.rs'),
            ]));
          },
        );
      }, timeout: const Timeout(Duration(minutes: 5)));
    }
  });

  group('an iOS build', () {
    // LC_BUILD_VERSION platforms: iOS 2, the iOS simulator 7.
    for (final (sdk, platform) in [
      (IOSSdk.iPhoneOS, 2),
      (IOSSdk.iPhoneSimulator, 7),
    ]) {
      test('for $sdk bundles one arm64 library for that platform', () async {
        await testCodeBuildHook(
          mainMethod: hook.main,
          targetOS: OS.iOS,
          targetArchitecture: Architecture.arm64,
          targetIOSSdk: sdk,
          // What Flutter 3.44.8 passes (`targetIOSVersion`).
          targetIOSVersion: 13,
          check: (input, output) {
            final asset = output.assets.code.single;
            expect(asset.id, 'package:key_core/key_core.dart');
            expect(asset.linkMode, DynamicLoadingBundled());
            final macho =
                _MachO(File.fromUri(asset.file!).readAsBytesSync());
            expect(macho.cpuType, 0x0100000c, reason: 'arm64');
            expect(macho.fileType, 6, reason: 'a dynamic library');
            expect(macho.platform, platform);
            // The simulator on Apple silicon starts at iOS 14.
            expect(macho.minimumOS, sdk == IOSSdk.iPhoneOS ? '13.0' : '14.0');
            // Xcode 27.1's `ld` refuses to link against a library whose
            // string table is not 8-byte aligned.
            expect(macho.stringTableOffset! % 8, 0,
                reason: 'string table at ${macho.stringTableOffset}');
            // Counted by kind rather than bounded in all: what is left is
            // the `kc_*` exports and the imports, which grow with each
            // network the core reads (the bound of 100 met them in 2f-6),
            // and an unstripped build holds thousands of local symbols.
            expect(macho.localOrDebugSymbols, 0,
                reason: 'local and debug symbols are stripped');
            expect(macho.symbolCount, greaterThan(0));
          },
        );
      }, timeout: const Timeout(Duration(minutes: 5)));
    }
  });

  group('the targets', () {
    test('the three Android ABIs and the macOS host are built', () {
      expect(hook.rustTarget(OS.android, Architecture.arm64),
          (triple: 'aarch64-linux-android', ndkClang: 'aarch64-linux-android'));
      expect(hook.rustTarget(OS.android, Architecture.arm), (
        triple: 'armv7-linux-androideabi',
        ndkClang: 'armv7a-linux-androideabi'
      ));
      expect(hook.rustTarget(OS.android, Architecture.x64),
          (triple: 'x86_64-linux-android', ndkClang: 'x86_64-linux-android'));
      expect(hook.rustTarget(OS.macOS, Architecture.arm64),
          (triple: 'aarch64-apple-darwin', ndkClang: null));
    });

    test('an iPhone and the simulator are told apart by the SDK', () {
      expect(hook.rustTarget(OS.iOS, Architecture.arm64, IOSSdk.iPhoneOS),
          (triple: 'aarch64-apple-ios', ndkClang: null));
      expect(
          hook.rustTarget(OS.iOS, Architecture.arm64, IOSSdk.iPhoneSimulator),
          (triple: 'aarch64-apple-ios-sim', ndkClang: null));
    });

    test('everything else is refused, the Intel simulator included', () {
      for (final (os, architecture, sdk) in [
        (OS.iOS, Architecture.arm64, null),
        (OS.iOS, Architecture.x64, IOSSdk.iPhoneSimulator),
        (OS.iOS, Architecture.x64, IOSSdk.iPhoneOS),
        (OS.android, Architecture.ia32, null),
        (OS.android, Architecture.riscv64, null),
        (OS.macOS, Architecture.x64, null),
        (OS.linux, Architecture.x64, null),
        (OS.windows, Architecture.x64, null),
      ]) {
        expect(hook.rustTarget(os, architecture, sdk), isNull,
            reason: '$os $architecture $sdk');
      }
    });
  });

  group('the NDK', () {
    // An NDK laid out as the SDK installs one, with only `source.properties`.
    Uri fakeNdkBin(String? revision) {
      final root = Directory.systemTemp.createTempSync('ndk');
      addTearDown(() => root.deleteSync(recursive: true));
      final bin = Directory(
          '${root.path}/toolchains/llvm/prebuilt/darwin-x86_64/bin')
        ..createSync(recursive: true);
      if (revision != null) {
        File('${root.path}/source.properties').writeAsStringSync(
            'Pkg.Desc = Android NDK\nPkg.Revision = $revision\n');
      }
      return bin.uri;
    }

    test('is the one tool/android_env.sh pins', () {
      final env = File('../tool/android_env.sh').readAsStringSync();
      expect(RegExp(r'^NDK_VERSION="([^"]+)"$', multiLine: true)
          .firstMatch(env)
          ?.group(1), hook.ndkRevision);
    });

    test('the installed one is read and accepted', () {
      expect(hook.ndkRevisionAt(bin), hook.ndkRevision);
      expect(() => hook.requireNdk(bin), returnsNormally);
    });

    test('another revision is refused, as Flutter would pass the newest', () {
      final other = fakeNdkBin('29.0.14206865');
      expect(hook.ndkRevisionAt(other), '29.0.14206865');
      expect(
          () => hook.requireNdk(other),
          throwsA(isA<BuildError>().having(
              (e) => e.message, 'message', contains('NDK 29.0.14206865'))));
    });

    test('an NDK that names no revision is refused', () {
      final unnamed = fakeNdkBin(null);
      expect(hook.ndkRevisionAt(unnamed), isNull);
      expect(() => hook.requireNdk(unnamed), throwsA(isA<BuildError>()));
    });

    // Through `buildKeyCore` rather than `main`: `build` exits the process on
    // a refusal, which would end this test run with it.
    test('the hook refuses another NDK before Cargo runs', () async {
      final other = fakeNdkBin('29.0.14206865');
      final temp = Directory.systemTemp.createTempSync('hook');
      addTearDown(() => temp.deleteSync(recursive: true));
      final input = BuildInputBuilder()
        ..setupShared(
          packageRoot: Directory.current.uri,
          packageName: 'key_core',
          outputDirectoryShared: temp.uri.resolve('shared/'),
          outputFile: temp.uri.resolve('output.json'),
        )
        ..setupBuildInput()
        ..config.setupBuild(linkingEnabled: false);
      CodeAssetExtension(
        targetArchitecture: Architecture.arm64,
        targetOS: OS.android,
        linkModePreference: LinkModePreference.dynamic,
        cCompiler: CCompilerConfig(
          compiler: other.resolve('clang'),
          linker: other.resolve('ld.lld'),
          archiver: other.resolve('llvm-ar'),
        ),
        android: AndroidCodeConfig(targetNdkApi: 30),
      ).setupBuildInput(input);
      await expectLater(
          hook.buildKeyCore(input.build(), BuildOutputBuilder()),
          throwsA(isA<BuildError>().having(
              (e) => e.message, 'message', contains('NDK 29.0.14206865'))));
      expect(Directory.fromUri(temp.uri.resolve('shared/cargo/')).existsSync(),
          isFalse);
    });
  });

  group('Cargo fetches nothing', () {
    test('it runs offline and locked, release, for one target', () {
      final arguments = hook.cargoArguments(
        triple: 'aarch64-linux-android',
        manifest: Uri.file('/k/Cargo.toml'),
        targetDirectory: Uri.directory('/t/cargo'),
      );
      expect(arguments.first, 'build');
      expect(arguments,
          containsAll(['--release', '--offline', '--locked']));
      final target = arguments.indexOf('--target');
      expect(arguments[target + 1], 'aarch64-linux-android');
    });

    test('rustup installs nothing, and Android links with the NDK for its API',
        () {
      final environment = hook.cargoEnvironment(
        triple: 'armv7-linux-androideabi',
        ndkClang: 'armv7a-linux-androideabi',
        ndkBin: Uri.directory('/ndk/bin'),
        api: 30,
      );
      expect(environment['RUSTUP_AUTO_INSTALL'], '0');
      expect(environment['CARGO_NET_OFFLINE'], 'true');
      expect(environment['CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER'],
          '/ndk/bin/armv7a-linux-androideabi30-clang');
      expect(environment['CC_armv7_linux_androideabi'],
          '/ndk/bin/armv7a-linux-androideabi30-clang');
      expect(environment['AR_armv7_linux_androideabi'], '/ndk/bin/llvm-ar');
      expect(environment['CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS'],
          contains('max-page-size=16384'));
    });

    test('the macOS host builds for the deployment target it is given', () {
      final environment = hook.cargoEnvironment(
          triple: 'aarch64-apple-darwin', macOSVersion: 13);
      expect(environment['RUSTUP_AUTO_INSTALL'], '0');
      expect(environment['MACOSX_DEPLOYMENT_TARGET'], '13.0');
      expect(environment.keys.where((k) => k.contains('LINKER')), isEmpty);
    });

    test('iOS builds for the deployment target it is given', () {
      final environment = hook.cargoEnvironment(
          triple: 'aarch64-apple-ios-sim', iOSVersion: 13);
      expect(environment['RUSTUP_AUTO_INSTALL'], '0');
      expect(environment['IPHONEOS_DEPLOYMENT_TARGET'], '13.0');
      expect(environment.keys.where((k) => k.contains('LINKER')), isEmpty);
    });

    test('on Apple targets the linker strips, and on Android rustc does', () {
      for (final triple in [
        'aarch64-apple-darwin',
        'aarch64-apple-ios',
        'aarch64-apple-ios-sim',
      ]) {
        final environment = hook.cargoEnvironment(triple: triple);
        final upper = triple.toUpperCase().replaceAll('-', '_');
        expect(environment['CARGO_PROFILE_RELEASE_STRIP'], 'none',
            reason: triple);
        expect(environment['CARGO_TARGET_${upper}_RUSTFLAGS'],
            allOf(contains('-Wl,-x'), contains('-Wl,-S')),
            reason: triple);
      }
      final android = hook.cargoEnvironment(
        triple: 'aarch64-linux-android',
        ndkClang: 'aarch64-linux-android',
        ndkBin: Uri.directory('/ndk/bin'),
        api: 30,
      );
      expect(android.containsKey('CARGO_PROFILE_RELEASE_STRIP'), isFalse);
    });
  });
}

/// The two things this test reads from an ELF file's headers.
final class _Elf {
  _Elf(this._bytes) {
    if (_bytes.length < 64 ||
        _bytes[0] != 0x7f ||
        _bytes[1] != 0x45 ||
        _bytes[2] != 0x4c ||
        _bytes[3] != 0x46) {
      throw const FormatException('not an ELF file');
    }
  }

  final Uint8List _bytes;

  ByteData get _data => ByteData.sublistView(_bytes);
  bool get _is64 => _bytes[4] == 2;

  int get machine => _data.getUint16(18, Endian.little);

  /// `p_align` of every PT_LOAD program header.
  List<int> get loadAlignments {
    final d = _data;
    final offset =
        _is64 ? d.getUint64(32, Endian.little) : d.getUint32(28, Endian.little);
    final size = d.getUint16(_is64 ? 54 : 42, Endian.little);
    final count = d.getUint16(_is64 ? 56 : 44, Endian.little);
    return [
      for (var i = 0; i < count; i++)
        if (d.getUint32(offset + i * size, Endian.little) == 1)
          _is64
              ? d.getUint64(offset + i * size + 48, Endian.little)
              : d.getUint32(offset + i * size + 28, Endian.little),
    ];
  }
}

/// What this test reads from a 64-bit Mach-O file's header and its
/// `LC_BUILD_VERSION` load command.
final class _MachO {
  _MachO(this._bytes) {
    if (_bytes.length < 32 || _data.getUint32(0, Endian.little) != 0xfeedfacf) {
      throw const FormatException('not a 64-bit Mach-O file');
    }
  }

  final Uint8List _bytes;

  ByteData get _data => ByteData.sublistView(_bytes);

  int get cpuType => _data.getUint32(4, Endian.little);
  int get fileType => _data.getUint32(12, Endian.little);

  /// The offset of `LC_BUILD_VERSION` (0x32), or null.
  int? get _buildVersion => _command(0x32);

  /// The offset of the load command [cmd], or null.
  int? _command(int cmd) {
    final count = _data.getUint32(16, Endian.little);
    var offset = 32;
    for (var i = 0; i < count; i++) {
      if (_data.getUint32(offset, Endian.little) == cmd) return offset;
      offset += _data.getUint32(offset + 4, Endian.little);
    }
    return null;
  }

  /// `LC_SYMTAB` (0x2): the number of symbols and where their names start.
  int? get symbolCount {
    final at = _command(0x2);
    return at == null ? null : _data.getUint32(at + 12, Endian.little);
  }

  /// The symbols that are neither exported nor imported — local ones, and
  /// debug (`N_STAB`) entries: each `nlist_64` is 16 bytes, its type the
  /// fifth byte, `N_EXT` (1) set on an exported or imported one.
  int? get localOrDebugSymbols {
    final at = _command(0x2);
    if (at == null) return null;
    final offset = _data.getUint32(at + 8, Endian.little);
    var count = 0;
    for (var i = 0; i < symbolCount!; i++) {
      final type = _data.getUint8(offset + 16 * i + 4);
      if (type & 0xe0 != 0 || type & 0x01 == 0) count++;
    }
    return count;
  }

  int? get stringTableOffset {
    final at = _command(0x2);
    return at == null ? null : _data.getUint32(at + 16, Endian.little);
  }

  int? get platform {
    final at = _buildVersion;
    return at == null ? null : _data.getUint32(at + 8, Endian.little);
  }

  /// `minos` as `major.minor`, with `.patch` when it is not zero.
  String? get minimumOS {
    final at = _buildVersion;
    if (at == null) return null;
    final v = _data.getUint32(at + 12, Endian.little);
    final patch = v & 0xff;
    return '${v >> 16}.${(v >> 8) & 0xff}${patch == 0 ? '' : '.$patch'}';
  }
}
