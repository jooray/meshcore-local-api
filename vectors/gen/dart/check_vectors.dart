// Cross-check of pairing.json and validators.json against MeshCore Open's Dart code.
//
// Copy `lib/services/local_api/local_api_crypto.dart` from the server branch next to this file,
// then run with the server project's package config (it provides pointycastle):
//
//   dart --packages=<meshcore-open>/.dart_tool/package_config.json \
//     check_vectors.dart <path to vectors folder>
//
// The `since` and name checks below are copies of the server's private helpers in
// `local_api_server.dart` (`_parseSince`, `_hashtagName`, `_regionName`); keep them in sync.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'local_api_crypto.dart';

int failures = 0;

void check(bool ok, String what) {
  if (!ok) {
    failures++;
    stdout.writeln('FAIL $what');
  }
}

DateTime? parseSince(Object? value) {
  if (value is String) {
    final parsed = DateTime.tryParse(value);
    if (parsed != null) return parsed.toUtc();
  } else if (value is int && value >= 0) {
    final millis = value > 100000000000 ? value : value * 1000;
    return DateTime.fromMillisecondsSinceEpoch(millis, isUtc: true);
  }
  return null;
}

final hashtagName = RegExp(r'^#[a-z0-9-]{1,31}$');
final regionName = RegExp(r'^[a-z0-9-]{1,30}$');

String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main(List<String> args) {
  final dir = args.isEmpty ? '..' : args.first;
  final pairing = jsonDecode(File('$dir/pairing.json').readAsStringSync());
  final validators = jsonDecode(File('$dir/validators.json').readAsStringSync());

  final key = pairing['testKey'];
  final raw = LocalApiCrypto.decodePublicKey(key['publicKey'] as String);
  check(raw != null, 'test key decodes');
  check(LocalApiCrypto.fingerprint(raw!) == key['fingerprint'], 'fingerprint');
  check(
    LocalApiCrypto.fingerprint(Uint8List(64)) ==
        pairing['fingerprintOfZeroBytes']['fingerprint'],
    'fingerprint of zero bytes',
  );
  final other = LocalApiCrypto.decodePublicKey(pairing['otherKey']['publicKey'] as String)!;

  for (final s in pairing['validSignatures'] as List) {
    final msg = s['message'] as String;
    for (final field in ['derBase64', 'rawBase64', 'highSRawBase64', 'highSDerBase64']) {
      check(LocalApiCrypto.verify(raw, msg, s[field] as String), '$field verifies for $msg');
      check(!LocalApiCrypto.verify(other, msg, s[field] as String), '$field fails for other key');
    }
    check(hex(SHA256Digest().process(Uint8List.fromList(utf8.encode(msg)))) == s['sha256Hex'],
        'sha256 of $msg');
  }

  final inv = pairing['invalidSignatures'];
  for (final c in inv['cases'] as List) {
    bool ok;
    try {
      ok = LocalApiCrypto.verify(raw, inv['message'] as String, c['signatureBase64'] as String);
    } catch (e) {
      ok = false;
      stdout.writeln('note: verify threw for "${c['why']}": $e');
    }
    check(!ok, 'refuses ${c['why']}');
  }
  for (final c in pairing['invalidPublicKeys'] as List) {
    check(LocalApiCrypto.decodePublicKey(c['publicKey'] as String) == null,
        'refuses key: ${c['why']}');
  }

  for (final c in validators['hashtagChannelNames']['cases'] as List) {
    check(hashtagName.hasMatch(c['name'] as String) == c['valid'], 'hashtag ${c['name']}');
  }
  for (final c in validators['hashtagChannelKeys']['cases'] as List) {
    final d = SHA256Digest().process(Uint8List.fromList(utf8.encode(c['name'] as String)));
    check(hex(d.sublist(0, 16)) == c['keyHex'], 'key for ${c['name']}');
  }
  for (final c in validators['regionNames']['cases'] as List) {
    check(regionName.hasMatch(c['name'] as String) == c['wellFormed'], 'region ${c['name']}');
  }
  for (final c in validators['since']['cases'] as List) {
    final got = parseSince(c['since']);
    final want = c['epochMs'];
    if (want == null) {
      check(got == null, 'since ${jsonEncode(c['since'])} must be refused (got $got)');
    } else {
      check(got?.millisecondsSinceEpoch == want, 'since ${jsonEncode(c['since'])}');
    }
  }

  stdout.writeln(failures == 0 ? 'all vectors pass' : '$failures failures');
  exit(failures == 0 ? 0 : 1);
}
