# Blind RSA Signatures for Dart

*Disclaimer: The author is NOT a cryptographer and this work has not been reviewed. This means that there is very likely a fatal flaw somewhere. this library is still experimental and not production-ready.*

A Dart implementation of RSA blind signatures based on David Chaum's algorithm. This library enables anonymous token issuance and verification where servers can sign messages without being able to link them to specific clients.

## Protocol Overview

A client asks a server to sign a message. The server receives the message, and returns the signature.

Using that (message, signature) pair, the client can locally compute a second, valid (message', signature') pair.

Anyone can verify that (message', signature') is valid for the server's public key, even though the server didn't see that pair before. But no one besides the client can link (message', signature') to (message, signature).

Using that scheme, a server can issue a token and verify that a client has a valid token, without being able to link both actions to the same client.

### How it works

1. **The client creates a random message, and blinds it with a random, secret factor.**
2. **The server receives the blind message, signs it and returns a blind signature.**
3. **From the blind signature, and knowing the secret factor, the client can locally compute a (message, signature) pair that can be verified using the server's public key.**
4. **Anyone, including the server, can thus later verify that (message, signature) is valid, without knowing when step 2 occurred.**

The scheme was designed by David Chaum, and was originally implemented for anonymizing DigiCash transactions.

## Installation

Add this to your `pubspec.yaml`:

```yaml
dependencies:
  blind_rsa_signatures:
    git:
      url: https://github.com/grunch/blind_rsa_signatures_dart.git
      ref: main
```

Then run:

```bash
dart pub get
```

## Usage

### Basic Example

```dart
import 'dart:typed_data';
import 'package:blind_rsa_signatures/blind_rsa_signatures.dart';

void main() async {
  // Configure options
  const options = Options.defaultOptions;
  
  // [SERVER]: Generate a RSA-2048 key pair
  final kp = await KeyPair.generate(null, 2048);
  final pk = kp.pk;  // Public key
  final sk = kp.sk;  // Secret key

  // [CLIENT]: Create a random message and blind it for the server whose public key is `pk`.
  // The client must store the message and the secret.
  final msg = Uint8List.fromList('test'.codeUnits);
  final blindingResult = pk.blind(null, msg, true, options);

  // [SERVER]: Compute a signature for a blind message, to be sent to the client.
  // The client secret should not be sent to the server.
  final blindSig = sk.blindSign(null, blindingResult.blindMessage, options);

  // [CLIENT]: Later, when the client wants to redeem a signed blind message,
  // using the blinding secret, it can locally compute the signature of the
  // original message.
  // The client then owns a new valid (message, signature) pair, and the
  // server cannot link it to a previous (blinded message, blind signature) pair.
  // Note that the finalization function also verifies that the new signature
  // is correct for the server public key.
  final sig = pk.finalize(
    blindSig,
    blindingResult.secret,
    blindingResult.messageRandomizer,
    msg,
    options,
  );

  // [SERVER/ANYONE]: A non-blind signature can be verified using the server's public key.
  final isValid = sig.verify(pk, blindingResult.messageRandomizer, msg, options);
  print('Signature is ${isValid ? 'valid' : 'invalid'}');
}
```

### Advanced Usage

#### Working with PEM Keys

```dart
// Generate keys and export to PEM
final keyPair = await KeyPair.generate(null, 2048);
final publicKeyPem = keyPair.publicKey.toPem();
final privateKeyPem = keyPair.secretKey.toPem();

// Import from PEM
final publicKey = PublicKey.fromPem(publicKeyPem);
final secretKey = SecretKey.fromPem(privateKeyPem);
final restoredKeyPair = KeyPair(publicKey: publicKey, secretKey: secretKey);
```

#### Working with DER Format

```dart
// Export public key to DER format (PKCS#8)
final derBytes = publicKey.toDer();

// Import from DER format (PKCS#8 first, falls back to PKCS#1)
final publicKeyFromDer = PublicKey.fromDer(derBytes);
```

#### Serialization

```dart
// Serialize blinding result to JSON
final blindingResult = publicKey.blind(null, message, true, options);
final json = blindingResult.toJson();

// Deserialize from JSON
final restoredResult = BlindingResult.fromJson(json);

// Serialize signature to base64
final signature = publicKey.finalize(blindSig, secret, randomizer, message, options);
final base64Sig = signature.toBase64();

// Deserialize from base64
final restoredSignature = Signature.fromBase64(base64Sig);
```

#### Custom Options

```dart
// Use custom hashing options
const customOptions = Options(
  hashId: 'SHA-512',
  saltLength: 32,
);

// Deterministic signatures for testing
final testOptions = Options.deterministicOptions();
```

#### Error Handling

```dart
try {
  final keyPair = await KeyPair.generate(null, 2048);
  final blindingResult = keyPair.pk.blind(null, message, true, options);
  // ... rest of protocol
} on KeyGenerationException catch (e) {
  print('Key generation failed: $e');
} on BlindingException catch (e) {
  print('Blinding failed: $e');
} on SignatureException catch (e) {
  print('Signing failed: $e');
} on VerificationException catch (e) {
  print('Verification failed: $e');
} on BlindSignatureException catch (e) {
  print('General blind signature error: $e');
}
```

## API Reference

### KeyPair

Generate and manage RSA key pairs.

```dart
// Generate new key pair
final keyPair = await KeyPair.generate(rng, keySize);

// Access keys
final publicKey = keyPair.pk;     // or keyPair.publicKey
final secretKey = keyPair.sk;     // or keyPair.secretKey

// Create from existing keys
final keyPair = KeyPair.fromPem(
  publicKeyPem: publicKeyPemString,
  privateKeyPem: privateKeyPemString,
);
```

## Security Considerations

### Key Size
- **Minimum 2048 bits**: This library enforces a minimum key size of 2048 bits for security.
- **Recommended 4096 bits**: For long-term security, consider using 4096-bit keys.

### Random Number Generation
- The library uses cryptographically secure random number generation.
- You can provide your own `SecureRandom` instance if needed.

### Message Randomizer
- Using a message randomizer (`useRandomizer: true`) provides additional security.
- It prevents certain attacks where the same message is blinded multiple times.

### Hash Functions
- Default: SHA-384 (recommended)
- Supported: SHA-256, SHA-384, SHA-512

## Performance

Key generation is computationally expensive and runs in an isolate to prevent UI blocking:

```dart
// Asynchronous (recommended for UI apps)
final keyPair = await KeyPair.generate(null, 2048);

// Synchronous (may block UI)
final keyPair = KeyPair.generateSync(null, 2048);
```

Typical performance on modern hardware:
- **Key Generation (2048-bit)**: ~500-2000ms
- **Blinding**: ~10-50ms
- **Blind Signing**: ~10-50ms
- **Finalization**: ~10-50ms
- **Verification**: ~1-10ms

## Compatibility

- **Dart**: >=3.0.0
- **Flutter**: >=3.0.0
- **Platforms**: All platforms supported by PointyCastle

## Dependencies

- `pointycastle`: RSA cryptographic operations
- `basic_utils`: PEM/DER key format handling
- `crypto`: Hash functions

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `dart test`
2. Code follows Dart conventions: `dart analyze`
3. Add tests for new features
4. Update documentation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **David Chaum**: Original blind signature algorithm inventor
- **PointyCastle**: Dart cryptographic library
- **Rust blind-rsa-signatures**: API design inspiration

## References

- [Chaum, David. "Blind signatures for untraceable payments"](https://link.springer.com/chapter/10.1007/978-1-4757-0602-4_18)
- [RFC 9474: RSA Blind Signatures](https://tools.ietf.org/rfc/rfc9474.txt)
- [PointyCastle Documentation](https://pub.dev/packages/pointycastle)