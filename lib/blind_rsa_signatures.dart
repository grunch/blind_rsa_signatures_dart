/// A Dart implementation of RSA blind signatures based on David Chaum's algorithm.
///
/// This library enables anonymous token issuance and verification where servers
/// can sign messages without being able to link them to specific clients.
///
/// ## Protocol Overview
///
/// A client asks a server to sign a message. The server receives the message,
/// and returns the signature.
///
/// Using that (message, signature) pair, the client can locally compute a second,
/// valid (message', signature') pair.
///
/// Anyone can verify that (message', signature') is valid for the server's public key,
/// even though the server didn't see that pair before. But no one besides the client
/// can link (message', signature') to (message, signature).
///
/// Using that scheme, a server can issue a token and verify that a client has a
/// valid token, without being able to link both actions to the same client.
///
/// 1. The client creates a random message, and blinds it with a random, secret factor.
/// 2. The server receives the blind message, signs it and returns a blind signature.
/// 3. From the blind signature, and knowing the secret factor, the client can locally
///    compute a (message, signature) pair that can be verified using the server's public key.
/// 4. Anyone, including the server, can thus later verify that (message, signature)
///    is valid, without knowing when step 2 occurred.
///
/// The scheme was designed by David Chaum, and was originally implemented for
/// anonymizing DigiCash transactions.
library blind_rsa_signatures;

export 'src/blinding_result.dart';
export 'src/exceptions.dart';
export 'src/key_pair.dart';
export 'src/options.dart';
export 'src/public_key.dart';
export 'src/secret_key.dart';
export 'src/signature.dart';
