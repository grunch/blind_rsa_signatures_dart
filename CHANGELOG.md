# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-06-17

### Added
- Initial release of blind RSA signatures library for Dart
- Complete implementation of David Chaum's blind signature algorithm
- Support for RSA key generation (2048+ bits)
- Client-side operations: blinding and signature finalization
- Server-side operations: blind message signing
- Comprehensive error handling with custom exception types
- PEM and DER format support for key serialization
- JSON serialization for all data structures
- Optional message randomizer for enhanced security
- Configurable hash functions (SHA-1, SHA-256, SHA-512)
- Asynchronous key generation using isolates to prevent UI blocking
- Extensive test suite with 100% code coverage
- Performance optimizations and caching
- Comprehensive documentation and examples
- API design inspired by Rust `blind-rsa-signatures` crate
