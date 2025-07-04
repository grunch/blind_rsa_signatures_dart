// ignore_for_file: avoid_catches_without_on_clauses

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:pointycastle/api.dart' show Digest;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';

import 'blinding_result.dart';
import 'exceptions.dart';
import 'options.dart';
import 'signature.dart' as brs_sig;

/// RSA public key for blind signature operations.
///
/// This class provides the client-side operations for blind signatures:
/// - Blinding messages before sending to server
/// - Finalizing (unblinding) signatures received from server
/// - Verifying signatures
class PublicKey {
  /// Create a PublicKey from PEM format string (supports both PKCS#1 and PKCS#8)
  factory PublicKey.fromPem(String pemKey) {
    try {
      RSAPublicKey basicUtilsKey;

      // Try PKCS#8 format first (SubjectPublicKeyInfo)
      if (pemKey.contains('BEGIN PUBLIC KEY')) {
        basicUtilsKey = CryptoUtils.rsaPublicKeyFromPem(pemKey);
      } else {
        // Fall back to PKCS#1 format (RSAPublicKey)
        basicUtilsKey = CryptoUtils.rsaPublicKeyFromPemPkcs1(pemKey);
      }

      final RSAPublicKey pointyCastleKey = pc.RSAPublicKey(
        basicUtilsKey.modulus!,
        basicUtilsKey.exponent!,
      );
      return PublicKey.fromRSAPublicKey(pointyCastleKey);
    } catch (e) {
      throw KeyException('Failed to parse RSA public key from PEM', e);
    }
  }

  PublicKey._(this._key);

  /// Create a PublicKey from PointyCastle RSAPublicKey
  factory PublicKey.fromRSAPublicKey(pc.RSAPublicKey key) {
    _validatePublicKey(key);
    return PublicKey._(key);
  }

  /// Create a PublicKey from DER format bytes (supports both PKCS#1 and PKCS#8)
  factory PublicKey.fromDer(Uint8List derBytes) {
    try {
      RSAPublicKey basicUtilsKey;

      // Try PKCS#8 format first (most common)
      try {
        basicUtilsKey = CryptoUtils.rsaPublicKeyFromDERBytes(derBytes);
      } catch (e) {
        // Fall back to PKCS#1 format
        final String pemKey = _constructPemFromDerPkcs1(derBytes);
        basicUtilsKey = CryptoUtils.rsaPublicKeyFromPemPkcs1(pemKey);
      }

      final RSAPublicKey pointyCastleKey = pc.RSAPublicKey(
        basicUtilsKey.modulus!,
        basicUtilsKey.exponent!,
      );
      return PublicKey.fromRSAPublicKey(pointyCastleKey);
    } catch (e) {
      throw KeyException('Failed to parse RSA public key from DER', e);
    }
  }

  /// The underlying PointyCastle RSA public key
  final pc.RSAPublicKey _key;

  /// Get the underlying PointyCastle RSA public key
  pc.RSAPublicKey get rsaPublicKey => _key;

  /// Get the key size in bits
  int get keySize => _key.modulus!.bitLength;

  /// Convert to PEM format (PKCS#8 - SubjectPublicKeyInfo)
  String toPem() {
    try {
      final RSAPublicKey basicUtilsKey =
          RSAPublicKey(_key.modulus!, _key.exponent!);
      return CryptoUtils.encodeRSAPublicKeyToPem(basicUtilsKey);
    } catch (e) {
      throw KeyException('Failed to encode RSA public key to PEM', e);
    }
  }

  /// Convert to DER format (PKCS#8 - SubjectPublicKeyInfo)
  Uint8List toDer() {
    try {
      final RSAPublicKey basicUtilsKey =
          RSAPublicKey(_key.modulus!, _key.exponent!);
      // Use PEM encoding then extract DER bytes since direct DER encoding method doesn't exist
      final String pem = CryptoUtils.encodeRSAPublicKeyToPem(basicUtilsKey);
      return CryptoUtils.getBytesFromPEMString(pem);
    } catch (e) {
      throw KeyException('Failed to encode RSA public key to DER', e);
    }
  }

  /// Blind a message for the server to sign.
  ///
  /// Parameters:
  /// - [rng]: Random number generator (can be null for default)
  /// - [message]: The message to blind
  /// - [useRandomizer]: Whether to use a message randomizer for additional security
  /// - [options]: Blinding options
  ///
  /// Returns a [BlindingResult] containing the blinded message and secret data.
  BlindingResult blind(
    pc.SecureRandom? rng,
    Uint8List message,
    bool useRandomizer,
    Options options,
  ) {
    _validateMessage(message);

    try {
      final SecureRandom random = rng ?? _getSecureRandom();
      final BigInt modulus = _key.modulus!;
      final BigInt exponent = _key.exponent!;

      // Generate message randomizer if requested
      Uint8List? messageRandomizer;
      if (useRandomizer) {
        messageRandomizer = _generateRandomBytes(32, random);
      }

      // Prepare message for hashing
      final Uint8List messageToHash = messageRandomizer != null
          ? Uint8List.fromList([...messageRandomizer, ...message])
          : message;

      final Uint8List hashedMessage = _hashMessage(messageToHash, options);
      final int modulusBits = modulus.bitLength;
      final int modulusBytes = (modulusBits + 7) ~/ 8;
      final int saltLen = _getSaltLength(options, modulusBits);

      // Apply EMSA-PSS padding
      final Uint8List paddedMessage = _emsaPssEncode(
          hashedMessage, modulusBits - 1, _generateRandomBytes(saltLen, random), options);
      final BigInt messageInt = _bytesToBigInt(paddedMessage);

      // Generate random blinding factor
      final BigInt blindingFactor = _generateBlindingFactor(modulus, random);

      // Blind the message: m' = m * r^e mod n
      final BigInt blindingFactorPowE =
          blindingFactor.modPow(exponent, modulus);
      final BigInt blindedMessage = (messageInt * blindingFactorPowE) % modulus;

      return BlindingResult(
        blindMessage: _bigIntToPaddedBytes(blindedMessage, modulusBytes),
        secret: _bigIntToPaddedBytes(blindingFactor, modulusBytes),
        message: message,
        messageRandomizer: messageRandomizer,
      );
    } catch (e) {
      throw BlindingException('Failed to blind message', e);
    }
  }

  /// Finalize (unblind) a signature received from the server.
  ///
  /// Parameters:
  /// - [blindSignature]: The blind signature from the server
  /// - [secret]: The blinding secret from the BlindingResult
  /// - [messageRandomizer]: Optional randomizer from the BlindingResult
  /// - [message]: The original message
  /// - [options]: Finalization options
  ///
  /// Returns a [Signature] that can be verified by anyone.
  brs_sig.Signature finalize(
    Uint8List blindSignature,
    Uint8List secret,
    Uint8List? messageRandomizer,
    Uint8List message,
    Options options,
  ) {
    try {
      _validateMessage(blindSignature);
      _validateMessage(secret);
      _validateMessage(message);

      final BigInt blindedSignatureInt = _bytesToBigInt(blindSignature);
      final BigInt blindingFactorInt = _bytesToBigInt(secret);
      final BigInt modulus = _key.modulus!;

      // Unblind the signature: s = s' * r^(-1) mod n
      final BigInt blindingFactorInverse =
          blindingFactorInt.modInverse(modulus);
      final BigInt unblindedSignature =
          (blindedSignatureInt * blindingFactorInverse) % modulus;

      final brs_sig.Signature signature =
          brs_sig.Signature(_bigIntToBytes(unblindedSignature));

      // Verify the signature is correct
      if (!signature.verify(this, messageRandomizer, message, options)) {
        throw FinalizationException('Finalized signature failed verification');
      }

      return signature;
    } catch (e) {
      throw FinalizationException('Failed to finalize signature', e);
    }
  }

  /// Verify a signature against a message.
  ///
  /// This is used internally by the Signature class and can also be called directly.
  bool verifySignature(
      Uint8List messageHash, Uint8List signature, Options options) {
    try {
      final BigInt signatureInt = _bytesToBigInt(signature);
      final BigInt exponent = _key.exponent!;
      final BigInt modulus = _key.modulus!;
      final int modulusBits = modulus.bitLength;

      // Verify signature: m = s^e mod n
      final BigInt verifiedMessageInt = signatureInt.modPow(exponent, modulus);
      final Uint8List verifiedBytes = _bigIntToFixedLengthBytes(verifiedMessageInt, (modulusBits + 7) ~/ 8);

      // Apply EMSA-PSS verification
      return _emsaPssVerify(messageHash, verifiedBytes, modulusBits - 1, options);
    } catch (e) {
      return false;
    }
  }

  // Helper methods (extracted from original BlindSignatureService)

  static void _validatePublicKey(pc.RSAPublicKey publicKey) {
    if (publicKey.modulus == null || publicKey.exponent == null) {
      throw const KeyException(
          'RSA public key modulus and exponent cannot be null');
    }
    if (publicKey.modulus!.bitLength < 2048) {
      throw const KeyException(
          'RSA key must be at least 2048 bits for security');
    }
  }

  static void _validateMessage(Uint8List data) {
    if (data.isEmpty) {
      throw const InvalidArgumentException('Message cannot be empty');
    }
  }

  static pc.SecureRandom _getSecureRandom() {
    final SecureRandom random = pc.SecureRandom('Fortuna');
    final Random seedSource = Random.secure();
    final List<int> seeds = List.generate(32, (i) => seedSource.nextInt(256));
    random.seed(pc.KeyParameter(Uint8List.fromList(seeds)));
    return random;
  }

  static Uint8List _generateRandomBytes(int length, pc.SecureRandom random) {
    final Uint8List bytes = Uint8List(length);
    for (int i = 0; i < length; i++) {
      bytes[i] = random.nextUint8();
    }
    return bytes;
  }

  static BigInt _generateBlindingFactor(
      BigInt modulus, pc.SecureRandom random) {
    BigInt blindingFactor;
    do {
      blindingFactor = _generateRandomBigInt(modulus.bitLength - 1, random);
    } while (blindingFactor.gcd(modulus) != BigInt.one ||
        blindingFactor <= BigInt.one);
    return blindingFactor;
  }

  static BigInt _generateRandomBigInt(int bitLength, pc.SecureRandom random) {
    final Uint8List bytes = Uint8List((bitLength + 7) ~/ 8);
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = random.nextUint8();
    }
    if (bitLength % 8 != 0) {
      bytes[0] &= (1 << (bitLength % 8)) - 1;
    }
    return _bytesToBigInt(bytes);
  }

  static Uint8List _hashMessage(Uint8List message, Options options) {
    final Digest hashInstance = _getHashDigest(options);
    hashInstance.reset();
    hashInstance.update(message, 0, message.length);
    final Uint8List hashed = Uint8List(hashInstance.digestSize);
    hashInstance.doFinal(hashed, 0);
    return hashed;
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

  static Uint8List _bigIntToFixedLengthBytes(BigInt bigInt, int length) {
    final Uint8List bytes = _bigIntToBytes(bigInt);
    if (bytes.length == length) {
      return bytes;
    } else if (bytes.length > length) {
      return Uint8List.fromList(bytes.sublist(bytes.length - length));
    } else {
      final Uint8List result = Uint8List(length);
      result.setRange(length - bytes.length, length, bytes);
      return result;
    }
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

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      return false;
    }
    int diff = 0;
    for (int i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  static String _constructPemFromDerPkcs1(Uint8List derBytes) {
    final String base64Content = base64Encode(derBytes);
    final StringBuffer buffer = StringBuffer();
    buffer.writeln('-----BEGIN RSA PUBLIC KEY-----');

    for (int i = 0; i < base64Content.length; i += 64) {
      final int end =
          (i + 64 < base64Content.length) ? i + 64 : base64Content.length;
      buffer.writeln(base64Content.substring(i, end));
    }

    buffer.write('-----END RSA PUBLIC KEY-----');
    return buffer.toString();
  }

  /// MGF1 XOR function
  static Uint8List _mgf1Xor(
      Uint8List seed, int maskLen, Digest hashInstance) {
    final Uint8List mask = Uint8List(maskLen);
    final int hLen = hashInstance.digestSize;
    final int numBlocks = (maskLen + hLen - 1) ~/ hLen;
    final Uint8List T = Uint8List(numBlocks * hLen);

    for (int i = 0; i < numBlocks; i++) {
      hashInstance.reset();
      hashInstance.update(seed, 0, seed.length);
      hashInstance.update(
          Uint8List.fromList([
            (i >> 24) & 0xFF,
            (i >> 16) & 0xFF,
            (i >> 8) & 0xFF,
            i & 0xFF
          ]),
          0,
          4);
      hashInstance.doFinal(T, i * hLen);
    }
    mask.setRange(0, maskLen, T.sublist(0, maskLen));
    return mask;
  }

  /// EMSA-PSS encoding function
  static Uint8List _emsaPssEncode(
      Uint8List mHash, int emBits, Uint8List salt, Options options) {
    final Digest hashInstance = _getHashDigest(options);
    final int hLen = hashInstance.digestSize;
    final int sLen = salt.length;
    final int emLen = (emBits + 7) ~/ 8;

    if (mHash.length != hLen) {
      throw const BlindingException('M_hash length is not equal to hLen');
    }
    if (emLen < hLen + sLen + 2) {
      throw const BlindingException('EM length is too small');
    }

    final Uint8List ps = Uint8List(emLen - sLen - hLen - 2); // All zeros
    final Uint8List db = Uint8List.fromList([...ps, 0x01, ...salt]);

    hashInstance.reset();
    hashInstance.update(Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0]), 0, 8);
    hashInstance.update(mHash, 0, mHash.length);
    hashInstance.update(salt, 0, salt.length);
    final Uint8List h = Uint8List(hLen);
    hashInstance.doFinal(h, 0);

    final Uint8List maskedDb = Uint8List(db.length);
    final Uint8List dbMask = _mgf1Xor(h, db.length, _getHashDigest(options));
    for (int i = 0; i < db.length; i++) {
      maskedDb[i] = db[i] ^ dbMask[i];
    }

    final int msbMask = 0xFF >> (8 * emLen - emBits);
    maskedDb[0] &= msbMask;

    final Uint8List em = Uint8List(emLen);
    em.setAll(0, maskedDb);
    em.setAll(maskedDb.length, h);
    em[emLen - 1] = 0xBC;

    return em;
  }

  /// EMSA-PSS verification function
  static bool _emsaPssVerify(
      Uint8List mHash, Uint8List em, int emBits, Options options) {
    final Digest hashInstance = _getHashDigest(options);
    final int hLen = hashInstance.digestSize;
    final int sLen = _getSaltLength(options, emBits);
    final int emLen = (emBits + 7) ~/ 8;

    if (mHash.length != hLen) {
      return false;
    }
    if (emLen < hLen + sLen + 2) {
      return false;
    }
    if (em[emLen - 1] != 0xBC) {
      return false;
    }

    final int msbMask = 0xFF >> (8 * emLen - emBits);
    if ((em[0] & (~msbMask)) != 0) {
      return false;
    }

    final Uint8List maskedDb = em.sublist(0, emLen - hLen - 1);
    final Uint8List h = em.sublist(emLen - hLen - 1, emLen - 1);

    final Uint8List dbMask = _mgf1Xor(h, maskedDb.length, _getHashDigest(options));
    final Uint8List db = Uint8List(maskedDb.length);
    for (int i = 0; i < maskedDb.length; i++) {
      db[i] = maskedDb[i] ^ dbMask[i];
    }

    db[0] &= msbMask;

    final int psLen = emLen - sLen - hLen - 2;
    for (int i = 0; i < psLen; i++) {
      if (db[i] != 0x00) {
        return false;
      }
    }
    if (db[psLen] != 0x01) {
      return false;
    }

    final Uint8List salt = db.sublist(psLen + 1, psLen + 1 + sLen);

    hashInstance.reset();
    hashInstance.update(Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0]), 0, 8);
    hashInstance.update(mHash, 0, mHash.length);
    hashInstance.update(salt, 0, salt.length);
    final Uint8List hPrime = Uint8List(hLen);
    hashInstance.doFinal(hPrime, 0);

    return _constantTimeEquals(h, hPrime);
  }

  static Digest _getHashDigest(Options options) {
    switch (options.hashId.toUpperCase()) {
      case 'SHA-256':
        return SHA256Digest();
      case 'SHA-384':
        return SHA384Digest();
      case 'SHA-512':
        return SHA512Digest();
      default:
        throw BlindingException('Unsupported hash function: ${options.hashId}');
    }
  }

  static int _getSaltLength(Options options, int keySizeBits) {
    if (options.deterministic) {
      return 0;
    }
    if (options.saltLength != Options.defaultSaltLength) {
      return options.saltLength;
    }
    // Default salt length is hash output size
    return _getHashDigest(options).digestSize;
  }

  static Uint8List _bigIntToPaddedBytes(BigInt bigInt, int length) {
    final Uint8List bytes = _bigIntToBytes(bigInt);
    if (bytes.length == length) {
      return bytes;
    } else if (bytes.length > length) {
      // If the BigInt is larger than the target length, truncate (shouldn't happen with correct RSA ops)
      return Uint8List.fromList(bytes.sublist(bytes.length - length));
    } else {
      // Pad with leading zeros
      final Uint8List paddedBytes = Uint8List(length);
      paddedBytes.setRange(length - bytes.length, length, bytes);
      return paddedBytes;
    }
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PublicKey &&
          runtimeType == other.runtimeType &&
          _key.modulus == other._key.modulus &&
          _key.exponent == other._key.exponent;

  @override
  int get hashCode => _key.modulus.hashCode ^ _key.exponent.hashCode;

  @override
  String toString() => 'PublicKey($keySize bits)';
}
