import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/export.dart' as pc;

import 'exceptions.dart';
import 'options.dart';

/// RSA secret (private) key for blind signature operations.
///
/// This class provides the server-side operation for blind signatures:
/// - Signing blinded messages from clients
class SecretKey {
  /// Create a SecretKey from PEM format string
  factory SecretKey.fromPem(String pemKey) {
    try {
      final RSAPrivateKey basicUtilsKey =
          CryptoUtils.rsaPrivateKeyFromPemPkcs1(pemKey);
      final RSAPrivateKey pointyCastleKey = pc.RSAPrivateKey(
        basicUtilsKey.modulus!,
        basicUtilsKey.privateExponent!,
        basicUtilsKey.p,
        basicUtilsKey.q,
      );
      return SecretKey.fromRSAPrivateKey(pointyCastleKey);
    } catch (e) {
      throw KeyException('Failed to parse RSA private key from PEM', e);
    }
  }

  /// Create a SecretKey from PointyCastle RSAPrivateKey
  factory SecretKey.fromRSAPrivateKey(pc.RSAPrivateKey key) {
    _validatePrivateKey(key);
    return SecretKey._(key);
  }
  SecretKey._(this._key);

  /// The underlying PointyCastle RSA private key
  final pc.RSAPrivateKey _key;

  /// Get the underlying PointyCastle RSA private key
  pc.RSAPrivateKey get rsaPrivateKey => _key;

  /// Get the key size in bits
  int get keySize => _key.modulus!.bitLength;

  /// Convert to PEM format
  String toPem() {
    try {
      final RSAPrivateKey basicUtilsKey = RSAPrivateKey(
        _key.modulus!,
        _key.privateExponent!,
        _key.p,
        _key.q,
      );
      return CryptoUtils.encodeRSAPrivateKeyToPemPkcs1(basicUtilsKey);
    } catch (e) {
      throw KeyException('Failed to encode RSA private key to PEM', e);
    }
  }

  /// Sign a blinded message from a client.
  ///
  /// This is the server-side operation that signs the blinded message
  /// without seeing the actual message content.
  ///
  /// Parameters:
  /// - [rng]: Random number generator (can be null for default, not used in current implementation)
  /// - [blindedMessage]: The blinded message received from the client
  /// - [options]: Signing options
  ///
  /// Returns the blind signature as bytes.
  Uint8List blindSign(
    pc.SecureRandom? rng,
    Uint8List blindedMessage,
    Options options,
  ) {
    _validateMessage(blindedMessage);

    try {
      final BigInt blindedMessageInt = _bytesToBigInt(blindedMessage);
      final BigInt privateExponent = _key.privateExponent!;
      final BigInt modulus = _key.modulus!;

      // Sign the blinded message: s' = (m')^d mod n
      final BigInt blindedSignature =
          blindedMessageInt.modPow(privateExponent, modulus);

      return _bigIntToBytes(blindedSignature);
    } catch (e) {
      throw SignatureException('Failed to sign blinded message', e);
    }
  }

  // Helper methods

  static void _validatePrivateKey(pc.RSAPrivateKey privateKey) {
    if (privateKey.modulus == null || privateKey.privateExponent == null) {
      throw const KeyException(
          'RSA private key modulus and exponent cannot be null');
    }
    if (privateKey.modulus!.bitLength < 2048) {
      throw const KeyException(
          'RSA key must be at least 2048 bits for security');
    }
  }

  static void _validateMessage(Uint8List data) {
    if (data.isEmpty) {
      throw const InvalidArgumentException('Message cannot be empty');
    }
  }

  static Uint8List _bigIntToBytes(BigInt bigInt) {
    if (bigInt == BigInt.zero) return Uint8List.fromList([0]);

    final int bitLength = bigInt.bitLength;
    final int byteLength = (bitLength + 7) >> 3;
    final Uint8List bytes = Uint8List(byteLength);

    BigInt temp = bigInt;
    for (int i = byteLength - 1; i >= 0; i--) {
      bytes[i] = (temp & BigInt.from(0xFF)).toInt();
      temp = temp >> 8;
    }

    return bytes;
  }

  static BigInt _bytesToBigInt(Uint8List bytes) {
    if (bytes.isEmpty) {
      return BigInt.zero;
    }

    BigInt result = BigInt.zero;
    final int length = bytes.length;

    if (length == 1) {
      return BigInt.from(bytes[0]);
    }

    for (int i = 0; i < length; i++) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }

    return result;
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SecretKey &&
          runtimeType == other.runtimeType &&
          _key.modulus == other._key.modulus &&
          _key.privateExponent == other._key.privateExponent;

  @override
  int get hashCode => _key.modulus.hashCode ^ _key.privateExponent.hashCode;

  @override
  String toString() => 'SecretKey($keySize bits)';
}
