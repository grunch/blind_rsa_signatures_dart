/// Base exception class for all blind signature related errors
abstract class BlindSignatureException implements Exception {
  const BlindSignatureException(this.message, [this.cause]);
  final String message;
  final dynamic cause;

  @override
  String toString() {
    if (cause != null) {
      return 'BlindSignatureException: $message (caused by: $cause)';
    }
    return 'BlindSignatureException: $message';
  }
}

/// Exception thrown when key generation fails
class KeyGenerationException extends BlindSignatureException {
  const KeyGenerationException(super.message, [super.cause]);
}

/// Exception thrown when key operations fail (invalid key, wrong format, etc.)
class KeyException extends BlindSignatureException {
  const KeyException(super.message, [super.cause]);
}

/// Exception thrown when blinding operations fail
class BlindingException extends BlindSignatureException {
  const BlindingException(super.message, [super.cause]);
}

/// Exception thrown when signature operations fail
class SignatureException extends BlindSignatureException {
  const SignatureException(super.message, [super.cause]);
}

/// Exception thrown when verification fails
class VerificationException extends BlindSignatureException {
  const VerificationException(super.message, [super.cause]);
}

/// Exception thrown when finalization (unblinding) fails
class FinalizationException extends BlindSignatureException {
  const FinalizationException(super.message, [super.cause]);
}

/// Exception thrown for invalid parameters or arguments
class InvalidArgumentException extends BlindSignatureException {
  const InvalidArgumentException(super.message, [super.cause]);
}
