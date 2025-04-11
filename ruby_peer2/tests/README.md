# Ruby Peer Tests

This directory contains tests for the Ruby peer-to-peer application.

## Test Structure

- `test_cryptography.rb` - Tests for cryptographic functions
- `test_identity.rb` - Tests for peer identity management
- `test_storage.rb` - Tests for secure file storage
- `test_runner.rb` - A script to run all tests

## Running Tests

To run all tests:

```bash
cd ruby_peer2
ruby tests/test_runner.rb
```

To run a specific test file:

```bash
cd ruby_peer2
ruby tests/test_cryptography.rb
```

## Test Dependencies

The tests use the following gems:
- `minitest` - Testing framework
- `colorize` - For colorized console output

Install them with:

```bash
gem install minitest colorize
```

## Test Coverage

The current tests cover:

1. **Cryptography**
   - Key generation
   - Signing and verification
   - PEM conversion and compatibility

2. **Identity Management** 
   - Identity creation
   - Loading existing identities
   - Identity payload generation and verification

3. **Secure Storage**
   - Password-based key derivation
   - File encryption and decryption
   - Secure file storage operations
   - File management and listing

## Adding New Tests

When adding new tests:

1. Create a new file named `test_[component].rb`
2. Require `minitest/autorun` and the relevant application files
3. Create a test class that inherits from `Minitest::Test`
4. Add test methods that start with `test_`
5. Use assertions to verify behavior 