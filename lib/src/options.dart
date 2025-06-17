import 'dart:typed_data';

/// Configuration options for RSA blind signature operations.
///
/// This class provides configuration parameters that control the behavior
/// of the blind signature scheme, including hash functions and salt parameters.
class Options {
  const Options({
    this.hashId = defaultHashId,
    this.saltLength = defaultSaltLength,
    this.deterministic = false,
    this.customSalt,
  });

  /// Default hash function identifier (SHA-256)
  static const String defaultHashId = 'SHA-256';

  /// Default salt length for PSS padding (auto-detect based on key size)
  static const int defaultSaltLength = -1;

  /// Hash function identifier used for message hashing
  final String hashId;

  /// Salt length for PSS padding. -1 means auto-detect based on key size
  final int saltLength;

  /// Whether to use deterministic signatures (for testing)
  final bool deterministic;

  /// Custom salt for deterministic signatures (only used when deterministic is true)
  final Uint8List? customSalt;

  /// Create default options suitable for most use cases
  static const Options defaultOptions = Options();

  /// Create options for deterministic signatures (useful for testing)
  static Options deterministicOptions({Uint8List? salt}) => Options(
        deterministic: true,
        customSalt: salt,
      );

  /// Create a copy of these options with modified parameters
  Options copyWith({
    String? hashId,
    int? saltLength,
    bool? deterministic,
    Uint8List? customSalt,
  }) =>
      Options(
        hashId: hashId ?? this.hashId,
        saltLength: saltLength ?? this.saltLength,
        deterministic: deterministic ?? this.deterministic,
        customSalt: customSalt ?? this.customSalt,
      );

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Options &&
          runtimeType == other.runtimeType &&
          hashId == other.hashId &&
          saltLength == other.saltLength &&
          deterministic == other.deterministic;

  @override
  int get hashCode =>
      hashId.hashCode ^ saltLength.hashCode ^ deterministic.hashCode;

  @override
  String toString() =>
      'Options(hashId: $hashId, saltLength: $saltLength, deterministic: $deterministic)';
}
