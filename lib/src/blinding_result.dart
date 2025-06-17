import 'dart:convert';
import 'dart:typed_data';

/// Result of a blinding operation containing all necessary data for later unblinding.
///
/// This class encapsulates the output of the blinding process, including:
/// - The blinded message that can be sent to the server
/// - The secret blinding factor needed for unblinding
/// - The original message for verification
/// - Optional message randomizer for additional security
class BlindingResult {
  const BlindingResult({
    required this.blindMessage,
    required this.secret,
    required this.message,
    this.messageRandomizer,
  });

  /// Create from JSON
  factory BlindingResult.fromJson(Map<String, dynamic> json) => BlindingResult(
        blindMessage: base64Decode(json['blind_message']),
        secret: base64Decode(json['secret']),
        message: base64Decode(json['message']),
        messageRandomizer: json['message_randomizer'] != null
            ? base64Decode(json['message_randomizer'])
            : null,
      );

  /// Create a BlindingResult from individual byte arrays
  factory BlindingResult.fromBytes({
    required Uint8List blindMessage,
    required Uint8List secret,
    required Uint8List message,
    Uint8List? messageRandomizer,
  }) =>
      BlindingResult(
        blindMessage: blindMessage,
        secret: secret,
        message: message,
        messageRandomizer: messageRandomizer,
      );

  /// The blinded message to be sent to the server for signing
  final Uint8List blindMessage;

  /// The secret blinding factor used to blind the message.
  /// This must be kept secret by the client and used during finalization.
  final Uint8List secret;

  /// The original message that was blinded
  final Uint8List message;

  /// Optional message randomizer for additional security
  final Uint8List? messageRandomizer;

  /// Convert to JSON for serialization
  Map<String, dynamic> toJson() => {
        'blind_message': base64Encode(blindMessage),
        'secret': base64Encode(secret),
        'message': base64Encode(message),
        if (messageRandomizer != null)
          'message_randomizer': base64Encode(messageRandomizer!),
      };

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is BlindingResult &&
          runtimeType == other.runtimeType &&
          _listEquals(blindMessage, other.blindMessage) &&
          _listEquals(secret, other.secret) &&
          _listEquals(message, other.message) &&
          _listEquals(messageRandomizer, other.messageRandomizer);

  @override
  int get hashCode =>
      blindMessage.hashCode ^
      secret.hashCode ^
      message.hashCode ^
      (messageRandomizer?.hashCode ?? 0);

  /// Helper method to compare Uint8List equality
  bool _listEquals(Uint8List? a, Uint8List? b) {
    if (a == null && b == null) return true;
    if (a == null || b == null) return false;
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  @override
  String toString() => 'BlindingResult('
      'blindMessage: ${blindMessage.length} bytes, '
      'secret: ${secret.length} bytes, '
      'message: ${message.length} bytes'
      '${messageRandomizer != null ? ', messageRandomizer: ${messageRandomizer!.length} bytes' : ''}'
      ')';
}
