import 'dart:typed_data';
import 'package:blind_rsa_signatures/blind_rsa_signatures.dart';

/// Example usage of the blind_rsa_signatures library.
///
/// This example demonstrates the complete blind signature protocol:
/// 1. Server generates RSA key pair
/// 2. Client blinds a message
/// 3. Server signs the blinded message
/// 4. Client unblinds the signature
/// 5. Anyone can verify the final signature
void main() async {
  // Configure options (similar to Rust API)
  const options = Options.defaultOptions;

  // [SERVER]: Generate a RSA-2048 key pair
  print('🔑 Generating RSA-2048 key pair...');
  final kp = await KeyPair.generate(null, 2048);
  final pk = kp.pk; // Public key
  final sk = kp.sk; // Secret key
  print('✅ Key pair generated successfully');

  // [CLIENT]: Create a random message and blind it for the server whose public key is `pk`.
  // The client must store the message and the secret.
  print('\n👤 Client: Blinding message...');
  final msg = Uint8List.fromList('test'.codeUnits);
  final blindingResult = pk.blind(null, msg, true, options);
  print('✅ Message blinded successfully');
  print('   Original message: "${String.fromCharCodes(msg)}"');
  print('   Blinded message: ${blindingResult.blindMessage.length} bytes');

  // [SERVER]: Compute a signature for a blind message, to be sent to the client.
  // The client secret should not be sent to the server.
  print('\n🖥️  Server: Signing blinded message...');
  final blindSig = sk.blindSign(null, blindingResult.blindMessage, options);
  print('✅ Blind signature generated');
  print('   Blind signature: ${blindSig.length} bytes');

  // [CLIENT]: Later, when the client wants to redeem a signed blind message,
  // using the blinding secret, it can locally compute the signature of the
  // original message.
  // The client then owns a new valid (message, signature) pair, and the
  // server cannot link it to a previous (blinded message, blind signature) pair.
  // Note that the finalization function also verifies that the new signature
  // is correct for the server public key.
  print('\n👤 Client: Finalizing (unblinding) signature...');
  final sig = pk.finalize(
    blindSig,
    blindingResult.secret,
    blindingResult.messageRandomizer,
    msg,
    options,
  );
  print('✅ Signature finalized and verified');
  print('   Final signature: ${sig.length} bytes');

  // [SERVER/ANYONE]: A non-blind signature can be verified using the server's public key.
  print('\n🔍 Anyone: Verifying signature...');
  final isValid =
      sig.verify(pk, blindingResult.messageRandomizer, msg, options);
  print('✅ Signature verification: ${isValid ? 'VALID' : 'INVALID'}');

  // Demonstrate serialization capabilities
  print('\n📦 Serialization demo...');

  // Convert keys to PEM format
  final publicKeyPem = pk.toPem();
  final privateKeyPem = sk.toPem();
  print('   Public key PEM: ${publicKeyPem.length} characters');
  print('   Private key PEM: ${privateKeyPem.length} characters');

  // Convert signature to base64
  final signatureBase64 = sig.toBase64();
  print('   Signature base64: $signatureBase64');

  // Serialize blinding result to JSON
  final blindingResultJson = blindingResult.toJson();
  print('   Blinding result JSON keys: ${blindingResultJson.keys.join(', ')}');

  print('\n🎉 Blind signature protocol completed successfully!');
  print('\nKey benefits demonstrated:');
  print('   ✓ Server cannot link blinded message to final signature');
  print(
      '   ✓ Client gets a valid signature without revealing the original message');
  print(
      '   ✓ Anyone can verify the final signature using the server\'s public key');
  print('   ✓ Complete anonymity and unlinkability achieved');
}

/// Advanced example demonstrating error handling and edge cases
void advancedExample() async {
  print('\n🚀 Advanced example with error handling...');

  try {
    // Generate keys with custom options
    final kp = await KeyPair.generate(null, 2048);

    // Test with different message types
    final messages = [
      'Short message',
      'A much longer message that tests the handling of variable-length content in the blind signature scheme',
      '🔐 Unicode message with emojis 🚀',
      '', // Empty message (should handle gracefully)
    ];

    for (final msgText in messages) {
      if (msgText.isEmpty) {
        print(
            '   Skipping empty message (would throw InvalidArgumentException)');
        continue;
      }

      final msg = Uint8List.fromList(msgText.codeUnits);

      // Test with and without message randomizer
      for (final useRandomizer in [true, false]) {
        final blindingResult =
            kp.pk.blind(null, msg, useRandomizer, Options.defaultOptions);
        final blindSig = kp.sk.blindSign(
            null, blindingResult.blindMessage, Options.defaultOptions);
        final sig = kp.pk.finalize(
          blindSig,
          blindingResult.secret,
          blindingResult.messageRandomizer,
          msg,
          Options.defaultOptions,
        );
        final isValid = sig.verify(kp.pk, blindingResult.messageRandomizer, msg,
            Options.defaultOptions);

        print(
            '   ✅ "${msgText.length > 20 ? '${msgText.substring(0, 20)}...' : msgText}" '
            '(randomizer: $useRandomizer) -> ${isValid ? 'VALID' : 'INVALID'}');
      }
    }

    print('✅ Advanced example completed successfully');
  } catch (e) {
    print('❌ Error in advanced example: $e');
  }
}

/// Performance benchmark example
void performanceExample() async {
  print('\n⚡ Performance benchmark...');

  final stopwatch = Stopwatch();

  // Benchmark key generation
  stopwatch.start();
  final kp = await KeyPair.generate(null, 2048);
  stopwatch.stop();
  print('   Key generation: ${stopwatch.elapsedMilliseconds}ms');

  final msg = Uint8List.fromList('Performance test message'.codeUnits);
  const iterations = 10;

  // Benchmark blinding
  stopwatch.reset();
  stopwatch.start();
  for (int i = 0; i < iterations; i++) {
    kp.pk.blind(null, msg, true, Options.defaultOptions);
  }
  stopwatch.stop();
  print(
      '   Blinding ($iterations iterations): ${stopwatch.elapsedMilliseconds}ms '
      '(${(stopwatch.elapsedMilliseconds / iterations).toStringAsFixed(1)}ms per operation)');

  // Benchmark signing
  final blindingResult = kp.pk.blind(null, msg, true, Options.defaultOptions);
  stopwatch.reset();
  stopwatch.start();
  for (int i = 0; i < iterations; i++) {
    kp.sk.blindSign(null, blindingResult.blindMessage, Options.defaultOptions);
  }
  stopwatch.stop();
  print(
      '   Blind signing ($iterations iterations): ${stopwatch.elapsedMilliseconds}ms '
      '(${(stopwatch.elapsedMilliseconds / iterations).toStringAsFixed(1)}ms per operation)');

  // Benchmark finalization
  final blindSig = kp.sk
      .blindSign(null, blindingResult.blindMessage, Options.defaultOptions);
  stopwatch.reset();
  stopwatch.start();
  for (int i = 0; i < iterations; i++) {
    kp.pk.finalize(blindSig, blindingResult.secret,
        blindingResult.messageRandomizer, msg, Options.defaultOptions);
  }
  stopwatch.stop();
  print(
      '   Finalization ($iterations iterations): ${stopwatch.elapsedMilliseconds}ms '
      '(${(stopwatch.elapsedMilliseconds / iterations).toStringAsFixed(1)}ms per operation)');

  print('✅ Performance benchmark completed');
}
