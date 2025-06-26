import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:blind_rsa_signatures/blind_rsa_signatures.dart';

void main() {
  group('Blind RSA Signatures', () {
    late KeyPair keyPair;
    late PublicKey publicKey;
    late SecretKey secretKey;
    const options = Options.defaultOptions;

    setUpAll(() async {
      // Generate a key pair for testing
      keyPair = await KeyPair.generate(null); // Default size is 2048 bits
      publicKey = keyPair.publicKey;
      secretKey = keyPair.secretKey;
    });

    group('KeyPair', () {
      test('should generate valid key pairs', () async {
        final kp = await KeyPair.generate(null);

        expect(kp.publicKey, isA<PublicKey>());
        expect(kp.secretKey, isA<SecretKey>());
        expect(kp.keySize, equals(2048));
        expect(kp.pk, equals(kp.publicKey));
        expect(kp.sk, equals(kp.secretKey));
      });

      test('should generate different keys on multiple calls', () async {
        final kp1 = await KeyPair.generate(null);
        final kp2 = await KeyPair.generate(null);

        expect(kp1.publicKey, isNot(equals(kp2.publicKey)));
        expect(kp1.secretKey, isNot(equals(kp2.secretKey)));
      });

      test('should reject small key sizes', () {
        expect(
          () => KeyPair.generate(null, 1024),
          throwsA(isA<KeyGenerationException>()),
        );
      });

      test('should export and import PEM format (PKCS#8)', () {
        final publicKeyPem = keyPair.publicKeyPem;
        final privateKeyPem = keyPair.privateKeyPem;

        expect(publicKeyPem, contains('-----BEGIN PUBLIC KEY-----'));
        expect(publicKeyPem, contains('-----END PUBLIC KEY-----'));
        expect(privateKeyPem, contains('-----BEGIN PRIVATE KEY-----'));
        expect(privateKeyPem, contains('-----END PRIVATE KEY-----'));

        final restoredKeyPair = KeyPair.fromPem(
          publicKeyPem: publicKeyPem,
          privateKeyPem: privateKeyPem,
        );

        expect(restoredKeyPair.publicKey, equals(keyPair.publicKey));
        expect(restoredKeyPair.secretKey, equals(keyPair.secretKey));
      });
    });

    group('PublicKey', () {
      test('should blind messages successfully', () {
        final message = Uint8List.fromList('test message'.codeUnits);
        final blindingResult = publicKey.blind(null, message, true, options);
        print(
            'blindingResult.messageRandomizer: ${blindingResult.messageRandomizer}');

        expect(blindingResult.blindMessage, isA<Uint8List>());
        expect(blindingResult.secret, isA<Uint8List>());
        expect(blindingResult.message, equals(message));
        expect(blindingResult.messageRandomizer, isA<Uint8List>());
        expect(blindingResult.messageRandomizer!.length, equals(32));
      });

      test('should blind messages without randomizer', () {
        final message = Uint8List.fromList('test message'.codeUnits);
        final blindingResult = publicKey.blind(null, message, false, options);

        expect(blindingResult.blindMessage, isA<Uint8List>());
        expect(blindingResult.secret, isA<Uint8List>());
        expect(blindingResult.message, equals(message));
        expect(blindingResult.messageRandomizer, isNull);
      });

      test('should produce different blinded messages for same input', () {
        final message = Uint8List.fromList('test message'.codeUnits);
        final result1 = publicKey.blind(null, message, true, options);
        final result2 = publicKey.blind(null, message, true, options);

        expect(result1.blindMessage, isNot(equals(result2.blindMessage)));
        expect(result1.secret, isNot(equals(result2.secret)));
      });

      test('should handle PEM format conversions', () {
        final pemString = publicKey.toPem();
        final restoredKey = PublicKey.fromPem(pemString);

        expect(restoredKey, equals(publicKey));
      });

      test('should handle DER format conversions', () {
        final derBytes = publicKey.toDer();
        final restoredKey = PublicKey.fromDer(derBytes);

        expect(restoredKey, equals(publicKey));
      });

      test('should reject invalid PEM format', () {
        expect(
          () => PublicKey.fromPem('invalid pem data'),
          throwsA(isA<KeyException>()),
        );
      });

      test('should reject empty messages', () {
        final emptyMessage = Uint8List(0);
        expect(
          () => publicKey.blind(null, emptyMessage, false, options),
          throwsA(isA<InvalidArgumentException>()),
        );
      });
    });

    group('SecretKey', () {
      test('should sign blinded messages', () {
        final message = Uint8List.fromList('test message'.codeUnits);
        final blindingResult = publicKey.blind(null, message, true, options);

        final blindSignature =
            secretKey.blindSign(null, blindingResult.blindMessage, options);

        expect(blindSignature, isA<Uint8List>());
        expect(blindSignature.length, greaterThan(0));
      });

      test('should handle PEM format conversions', () {
        final pemString = secretKey.toPem();
        final restoredKey = SecretKey.fromPem(pemString);

        expect(restoredKey, equals(secretKey));
      });

      test('should reject invalid PEM format', () {
        expect(
          () => SecretKey.fromPem('invalid pem data'),
          throwsA(isA<KeyException>()),
        );
      });

      test('should reject empty blinded messages', () {
        final emptyMessage = Uint8List(0);
        expect(
          () => secretKey.blindSign(null, emptyMessage, options),
          throwsA(isA<InvalidArgumentException>()),
        );
      });
    });

    group('Complete Protocol', () {
      test('should complete full blind signature protocol with randomizer', () {
        final message = Uint8List.fromList('test message'.codeUnits);

        // Client blinds message
        final blindingResult = publicKey.blind(null, message, true, options);

        // Server signs blinded message
        final blindSignature =
            secretKey.blindSign(null, blindingResult.blindMessage, options);

        // Client finalizes signature
        final signature = publicKey.finalize(
          blindSignature,
          blindingResult.secret,
          blindingResult.messageRandomizer,
          message,
          options,
        );

        // Anyone can verify the signature
        final isValid = signature.verify(
            publicKey, blindingResult.messageRandomizer, message, options);

        expect(isValid, isTrue);
      });

      test('should complete full blind signature protocol without randomizer',
          () {
        final message = Uint8List.fromList('test message'.codeUnits);

        final blindingResult = publicKey.blind(null, message, false, options);
        final blindSignature =
            secretKey.blindSign(null, blindingResult.blindMessage, options);
        final signature = publicKey.finalize(
          blindSignature,
          blindingResult.secret,
          blindingResult.messageRandomizer,
          message,
          options,
        );

        final isValid = signature.verify(
            publicKey, blindingResult.messageRandomizer, message, options);

        expect(isValid, isTrue);
      });

      test('should handle different message lengths', () {
        final messages = [
          'short',
          'This is a much longer message that tests how the blind signature protocol handles variable-length content',
          '🔐 Unicode characters and emojis 🚀',
        ];

        for (final msgText in messages) {
          final message = Uint8List.fromList(msgText.codeUnits);

          final blindingResult = publicKey.blind(null, message, true, options);
          final blindSignature =
              secretKey.blindSign(null, blindingResult.blindMessage, options);
          final signature = publicKey.finalize(
            blindSignature,
            blindingResult.secret,
            blindingResult.messageRandomizer,
            message,
            options,
          );

          final isValid = signature.verify(
              publicKey, blindingResult.messageRandomizer, message, options);

          expect(isValid, isTrue, reason: 'Failed for message: $msgText');
        }
      });

      test('should reject signature verification with wrong message', () {
        final message1 = Uint8List.fromList('original message'.codeUnits);
        final message2 = Uint8List.fromList('different message'.codeUnits);

        final blindingResult = publicKey.blind(null, message1, true, options);
        final blindSignature =
            secretKey.blindSign(null, blindingResult.blindMessage, options);
        final signature = publicKey.finalize(
          blindSignature,
          blindingResult.secret,
          blindingResult.messageRandomizer,
          message1,
          options,
        );

        // Verify with wrong message should fail
        final isValid = signature.verify(
            publicKey, blindingResult.messageRandomizer, message2, options);

        expect(isValid, isFalse);
      });

      test('should reject signature verification with wrong public key',
          () async {
        final message = Uint8List.fromList('test message'.codeUnits);
        final otherKeyPair = await KeyPair.generate(null, 2048);

        final blindingResult = publicKey.blind(null, message, true, options);
        final blindSignature =
            secretKey.blindSign(null, blindingResult.blindMessage, options);
        final signature = publicKey.finalize(
          blindSignature,
          blindingResult.secret,
          blindingResult.messageRandomizer,
          message,
          options,
        );

        // Verify with wrong public key should fail
        final isValid = signature.verify(otherKeyPair.publicKey,
            blindingResult.messageRandomizer, message, options);

        expect(isValid, isFalse);
      });
    });

    group('Signature', () {
      late Signature validSignature;
      late Uint8List testMessage;
      late Uint8List? testRandomizer;

      setUp(() {
        testMessage = Uint8List.fromList('test signature'.codeUnits);
        final blindingResult =
            publicKey.blind(null, testMessage, true, options);
        testRandomizer = blindingResult.messageRandomizer;
        final blindSignature =
            secretKey.blindSign(null, blindingResult.blindMessage, options);
        validSignature = publicKey.finalize(
          blindSignature,
          blindingResult.secret,
          blindingResult.messageRandomizer,
          testMessage,
          options,
        );
      });

      test('should convert to and from base64', () {
        final base64String = validSignature.toBase64();
        final restoredSignature = Signature.fromBase64(base64String);

        expect(restoredSignature, equals(validSignature));
      });

      test('should serialize to and from JSON', () {
        final json = validSignature.toJson();
        final restoredSignature = Signature.fromJson(json);

        expect(restoredSignature, equals(validSignature));
      });

      test('should reject invalid base64', () {
        expect(
          () => Signature.fromBase64('invalid base64!@#'),
          throwsA(isA<SignatureException>()),
        );
      });

      test('should verify correctly', () {
        final isValid = validSignature.verify(
            publicKey, testRandomizer, testMessage, options);
        expect(isValid, isTrue);
      });

      test('should have correct length property', () {
        expect(validSignature.length, equals(validSignature.bytes.length));
      });
    });

    group('BlindingResult', () {
      late BlindingResult blindingResult;

      setUp(() {
        final message = Uint8List.fromList('test blinding'.codeUnits);
        blindingResult = publicKey.blind(null, message, true, options);
      });

      test('should serialize to and from JSON', () {
        final json = blindingResult.toJson();
        final restored = BlindingResult.fromJson(json);

        expect(restored, equals(blindingResult));
      });

      test('should serialize to and from JSON without randomizer', () {
        final message = Uint8List.fromList('test blinding'.codeUnits);
        final result = publicKey.blind(null, message, false, options);

        final json = result.toJson();
        final restored = BlindingResult.fromJson(json);

        expect(restored, equals(result));
        expect(restored.messageRandomizer, isNull);
      });

      test('should have correct string representation', () {
        final str = blindingResult.toString();
        expect(str, contains('BlindingResult'));
        expect(str, contains('blindMessage:'));
        expect(str, contains('secret:'));
        expect(str, contains('message:'));
      });

      test('should support equality comparison', () {
        final message = Uint8List.fromList('test blinding'.codeUnits);
        final result1 = publicKey.blind(null, message, false, options);
        final result2 = BlindingResult.fromJson(result1.toJson());

        expect(result1, equals(result2));
      });
    });

    group('Options', () {
      test('should use default options', () {
        const opts = Options.defaultOptions;

        expect(Options.defaultOptions.hashId, 'SHA-384');
        expect(opts.saltLength, equals(-1));
        expect(opts.deterministic, isFalse);
        expect(opts.customSalt, isNull);
      });

      test('should create deterministic options', () {
        final opts = Options.deterministicOptions();

        expect(opts.deterministic, isTrue);
        expect(opts.customSalt, isNull);
      });

      test('should create deterministic options with custom salt', () {
        final salt = Uint8List.fromList([1, 2, 3, 4]);
        final opts = Options.deterministicOptions(salt: salt);

        expect(opts.deterministic, isTrue);
        expect(opts.customSalt, equals(salt));
      });

      test('should support copyWith', () {
        const original = Options.defaultOptions;
        final modified =
            original.copyWith(hashId: 'SHA-512', deterministic: true);

        expect(modified.hashId, equals('SHA-512'));
        expect(modified.deterministic, isTrue);
        expect(modified.saltLength, equals(original.saltLength));
      });

      test('should support equality', () {
        const opts1 = Options(hashId: 'SHA-256', saltLength: 32);
        const opts2 = Options(hashId: 'SHA-256', saltLength: 32);
        const opts3 = Options(hashId: 'SHA-512', saltLength: 32);

        expect(opts1, equals(opts2));
        expect(opts1, isNot(equals(opts3)));
      });

      test('should have string representation', () {
        const opts =
            Options(hashId: 'SHA-256', saltLength: 32, deterministic: true);
        final str = opts.toString();

        expect(str, contains('Options'));
        expect(str, contains('SHA-256'));
        expect(str, contains('32'));
        expect(str, contains('true'));
      });
    });

    group('Error Handling', () {
      test('should throw appropriate exceptions for invalid operations', () {
        final message = Uint8List.fromList('test'.codeUnits);
        final invalidSignature = Uint8List.fromList([1, 2, 3, 4]);
        final invalidSecret = Uint8List.fromList([5, 6, 7, 8]);

        expect(
          () => publicKey.finalize(
              invalidSignature, invalidSecret, null, message, options),
          throwsA(isA<FinalizationException>()),
        );
      });

      test('should handle verification errors gracefully', () {
        final signature = Signature(Uint8List.fromList([1, 2, 3, 4]));
        final message = Uint8List.fromList('test'.codeUnits);

        // Should return false, not throw
        final isValid = signature.verify(publicKey, null, message, options);
        expect(isValid, isFalse);
      });
    });

    group('Performance Tests', () {
      test('should complete operations within reasonable time', () async {
        final stopwatch = Stopwatch();

        // Test blinding performance
        final message = Uint8List.fromList('performance test'.codeUnits);

        stopwatch.start();
        final blindingResult = publicKey.blind(null, message, true, options);
        stopwatch.stop();

        expect(stopwatch.elapsedMilliseconds, lessThan(1000)); // Should be fast

        // Test signing performance
        stopwatch.reset();
        stopwatch.start();
        final blindSignature =
            secretKey.blindSign(null, blindingResult.blindMessage, options);
        stopwatch.stop();

        expect(stopwatch.elapsedMilliseconds, lessThan(1000));

        // Test finalization performance
        stopwatch.reset();
        stopwatch.start();
        final signature = publicKey.finalize(
          blindSignature,
          blindingResult.secret,
          blindingResult.messageRandomizer,
          message,
          options,
        );
        stopwatch.stop();

        expect(stopwatch.elapsedMilliseconds, lessThan(1000));

        // Test verification performance
        stopwatch.reset();
        stopwatch.start();
        final isValid = signature.verify(
            publicKey, blindingResult.messageRandomizer, message, options);
        stopwatch.stop();

        expect(isValid, isTrue);
        expect(stopwatch.elapsedMilliseconds, lessThan(500));
      });
    });
  });
}
