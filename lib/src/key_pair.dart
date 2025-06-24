import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/export.dart' as pc;

import 'exceptions.dart';
import 'public_key.dart' as brs_pk;
import 'secret_key.dart' as brs_sk;

/// RSA key pair for blind signature operations.
///
/// Contains both public and secret keys needed for the complete
/// blind signature protocol.
class KeyPair {
  const KeyPair({
    required this.publicKey,
    required this.secretKey,
  });

  /// Create a KeyPair from PEM formatted strings
  factory KeyPair.fromPem({
    required String publicKeyPem,
    required String privateKeyPem,
  }) =>
      KeyPair(
        publicKey: brs_pk.PublicKey.fromPem(publicKeyPem),
        secretKey: brs_sk.SecretKey.fromPem(privateKeyPem),
      );

  /// Create a KeyPair from existing PointyCastle keys
  factory KeyPair.fromRSAKeyPair(
          pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> keyPair) =>
      KeyPair(
        publicKey: brs_pk.PublicKey.fromRSAPublicKey(keyPair.publicKey),
        secretKey: brs_sk.SecretKey.fromRSAPrivateKey(keyPair.privateKey),
      );

  /// The public key (for client operations)
  final brs_pk.PublicKey publicKey;

  /// The secret key (for server operations)
  final brs_sk.SecretKey secretKey;

  /// Convenience getters matching the Rust API
  brs_pk.PublicKey get pk => publicKey;
  brs_sk.SecretKey get sk => secretKey;

  /// Generate a new RSA key pair for blind signatures.
  ///
  /// Parameters:
  /// - [rng]: Random number generator (can be null for default)
  /// - [keySize]: Key size in bits (minimum 2048, default 2048)
  ///
  /// Returns a [Future<KeyPair>] that completes with the generated key pair.
  ///
  /// The key generation runs in an isolate to avoid blocking the UI thread.
  static Future<KeyPair> generate(SecureRandom? rng,
      [int keySize = 2048]) async {
    if (keySize < 2048) {
      throw const KeyGenerationException(
          'Key size must be at least 2048 bits for security');
    }

    try {
      // Run key generation in isolate to prevent UI blocking
      final Map<String, String> serializedKeyPair =
          await Isolate.run(() => _generateKeyPairInIsolate(keySize));

      // Deserialize the keys on the main isolate
      final brs_pk.PublicKey publicKey =
          brs_pk.PublicKey.fromPem(serializedKeyPair['publicKey']!);
      final brs_sk.SecretKey secretKey =
          brs_sk.SecretKey.fromPem(serializedKeyPair['privateKey']!);

      return KeyPair(publicKey: publicKey, secretKey: secretKey);
    } catch (e) {
      throw KeyGenerationException('Failed to generate RSA key pair', e);
    }
  }

  /// Generate key pair synchronously (not recommended for UI thread)
  ///
  /// This method generates keys on the current thread and may cause
  /// UI blocking. Use [generate] instead for UI applications.
  static KeyPair generateSync(SecureRandom? rng, [int keySize = 2048]) {
    if (keySize < 2048) {
      throw const KeyGenerationException(
          'Key size must be at least 2048 bits for security');
    }

    try {
      final Map<String, String> serializedKeyPair =
          _generateKeyPairInIsolate(keySize);

      final brs_pk.PublicKey publicKey =
          brs_pk.PublicKey.fromPem(serializedKeyPair['publicKey']!);
      final brs_sk.SecretKey secretKey =
          brs_sk.SecretKey.fromPem(serializedKeyPair['privateKey']!);

      return KeyPair(publicKey: publicKey, secretKey: secretKey);
    } catch (e) {
      throw KeyGenerationException('Failed to generate RSA key pair', e);
    }
  }

  /// Get the key size in bits
  int get keySize => publicKey.keySize;

  /// Export public key to PEM format
  String get publicKeyPem => publicKey.toPem();

  /// Export private key to PEM format
  String get privateKeyPem => secretKey.toPem();

  /// Export public key to DER format
  Uint8List get publicKeyDer => publicKey.toDer();

  // Private helper method for key generation
  static Map<String, String> _generateKeyPairInIsolate(int keySize) {
    const int publicExponent = 65537;

    // Initialize secure random
    final pc.SecureRandom secureRandom = pc.SecureRandom('Fortuna');
    final Random seedSource = Random.secure();
    final List<int> seeds =
        List.generate(32, (int i) => seedSource.nextInt(256));
    secureRandom.seed(pc.KeyParameter(Uint8List.fromList(seeds)));

    // Generate RSA key pair
    final pc.RSAKeyGenerator keyGen = pc.RSAKeyGenerator();
    keyGen.init(pc.ParametersWithRandom(
      pc.RSAKeyGeneratorParameters(
        BigInt.from(publicExponent),
        keySize,
        64, // certainty for prime generation
      ),
      secureRandom,
    ));

    final pc.AsymmetricKeyPair<pc.PublicKey, pc.PrivateKey> keyPair =
        keyGen.generateKeyPair();
    final pc.RSAPublicKey publicKey = keyPair.publicKey as pc.RSAPublicKey;
    final pc.RSAPrivateKey privateKey = keyPair.privateKey as pc.RSAPrivateKey;

    // Convert to PEM strings for serialization across isolate boundary
    final String publicKeyPem = _rsaPublicKeyToPem(publicKey);
    final String privateKeyPem = _rsaPrivateKeyToPem(privateKey);

    return {
      'publicKey': publicKeyPem,
      'privateKey': privateKeyPem,
    };
  }

  static String _rsaPublicKeyToPem(pc.RSAPublicKey publicKey) {
    final pc.RSAPublicKey basicUtilsKey =
        RSAPublicKey(publicKey.modulus!, publicKey.exponent!);
    return CryptoUtils.encodeRSAPublicKeyToPem(basicUtilsKey);
  }

  static String _rsaPrivateKeyToPem(pc.RSAPrivateKey privateKey) {
    final pc.RSAPrivateKey basicUtilsKey = RSAPrivateKey(
      privateKey.modulus!,
      privateKey.privateExponent!,
      privateKey.p,
      privateKey.q,
    );
    return CryptoUtils.encodeRSAPrivateKeyToPem(basicUtilsKey);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is KeyPair &&
          runtimeType == other.runtimeType &&
          publicKey == other.publicKey &&
          secretKey == other.secretKey;

  @override
  int get hashCode => publicKey.hashCode ^ secretKey.hashCode;

  @override
  String toString() => 'KeyPair($keySize bits)';
}
