import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' show Digest;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';

import 'exceptions.dart';
import 'options.dart';
import 'public_key.dart';

/// Represents a finalized (unblinded) RSA signature.
///
/// This class encapsulates a signature that has been unblinded by the client
/// and can be verified by anyone using the server's public key.
class Signature {
  const Signature(this.bytes);

  /// Create from JSON
  factory Signature.fromJson(Map<String, dynamic> json) =>
      Signature(base64Decode(json['signature']));

  /// Create a signature from base64 encoded string
  factory Signature.fromBase64(String base64Signature) {
    try {
      return Signature(base64Decode(base64Signature));
    } catch (e) {
      throw SignatureException('Invalid base64 signature format', e);
    }
  }

  /// The signature bytes
  final Uint8List bytes;

  /// Convert signature to base64 string for transmission/storage
  String toBase64() => base64Encode(bytes);

  /// Verify this signature against a message using the given public key.
  ///
  /// Parameters:
  /// - [publicKey]: The server's public key
  /// - [messageRandomizer]: Optional randomizer used during blinding
  /// - [message]: The original message that was signed
  /// - [options]: Verification options
  ///
  /// Returns true if the signature is valid, false otherwise.
  ///
  /// Throws [VerificationException] if verification fails due to invalid parameters.
  bool verify(
    PublicKey publicKey,
    Uint8List? messageRandomizer,
    Uint8List message,
    Options options,
  ) {
    try {
      // Prepare the message for verification (same as during signing)
      final Uint8List messageToVerify =
          _prepareMessage(message, messageRandomizer, options);

      // Verify using RSA public key
      return publicKey.verifySignature(messageToVerify, bytes, options);
    } catch (e) {
      throw VerificationException('Signature verification failed', e);
    }
  }

  /// Prepare message for verification (apply same transformations as during signing)
  Uint8List _prepareMessage(
      Uint8List message, Uint8List? messageRandomizer, Options options) {
    if (messageRandomizer != null) {
      // Combine randomizer with message
      final Uint8List combined =
          Uint8List(messageRandomizer.length + message.length);
      combined.setRange(0, messageRandomizer.length, messageRandomizer);
      combined.setRange(messageRandomizer.length, combined.length, message);
      return _hashMessage(combined, options);
    } else {
      return _hashMessage(message, options);
    }
  }

  /// Hash message using the specified hash function
  Uint8List _hashMessage(Uint8List message, Options options) {
    final Digest hashInstance = _getHashDigest(options);
    hashInstance.reset();
    hashInstance.update(message, 0, message.length);
    final Uint8List hashed = Uint8List(hashInstance.digestSize);
    hashInstance.doFinal(hashed, 0);
    return hashed;
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
        throw VerificationException('Unsupported hash function: ${options.hashId}');
    }
  }

  /// Get the length of the signature in bytes
  int get length => bytes.length;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Signature &&
          runtimeType == other.runtimeType &&
          _listEquals(bytes, other.bytes);

  @override
  int get hashCode => bytes.hashCode;

  /// Helper method to compare Uint8List equality
  bool _listEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  @override
  String toString() => 'Signature(${bytes.length} bytes)';

  /// Convert to JSON for serialization
  Map<String, dynamic> toJson() => {
        'signature': base64Encode(bytes),
      };
}
