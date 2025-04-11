# Ruby-Python Interoperability Testing

This directory contains tests for verifying interoperability between the Ruby and Python P2P clients.

## Setup

### Dependencies

Before running the tests, ensure you have the following dependencies installed:

#### Ruby dependencies
```bash
gem install minitest colorize
```

#### Python dependencies
```bash
pip install cryptography
```

### Test Files

There are two main files for interoperability testing:

1. `test_python_interop.rb` - Ruby tests that connect to a running Python peer
2. `python_test_peer.py` - A simplified Python peer for testing

## Running the Interoperability Tests

### Step 1: Start the Python Test Peer

First, start the Python test peer in a terminal:

```bash
cd ruby_peer2/tests
python python_test_peer.py --auto
```

Options:
- `--auto`: Automatically accept file transfer requests (recommended for testing)
- `--port PORT`: Use a different port (default: 5003)

The Python peer will start and create a test file in the Files directory. It provides a command line interface where you can:
- Type `list` to show available files
- Type `key` to view the current session key
- Type `auto` to toggle auto-acceptance of file requests
- Type `exit` to stop the server

### Step 2: Run the Ruby Tests

In a different terminal, run the Ruby interoperability tests:

```bash
cd ruby_peer2
ruby tests/test_python_interop.rb
```

By default, the tests will connect to a Python peer at 127.0.0.1:5003. You can override these settings with environment variables:

```bash
PYTHON_PEER_IP=192.168.1.100 PYTHON_PEER_PORT=5003 ruby tests/test_python_interop.rb
```

## What's Being Tested

The interoperability tests verify:

1. **Key Exchange Protocol** - Ensures that Ruby and Python can perform ECDH key exchange and derive the same session key
2. **File List Protocol** - Verifies Ruby can request and parse file listings from Python
3. **File Transfer Workflow** - Tests a complete workflow of key exchange and file listing

There's also a skipped test for file transfer that you can enable by removing the `skip` line. This test requires manual confirmation on the Python side unless the `--auto` flag is used.

## Troubleshooting

### Test peer not available

If you see "Python peer is not running" messages, make sure:
1. The Python test peer is running
2. It's using the expected port
3. There are no firewall issues blocking connections

### Key exchange failures

If key exchange fails:
1. Check that both implementations are using the same curve (secp256r1/prime256v1)
2. Verify the HKDF parameters match (especially the info string 'p2p-key-exchange')

### File transfer issues

If file transfers fail:
1. Ensure files exist in the Python peer's Files directory
2. Check that encryption parameters match (AES-GCM with correct key sizes)
3. Verify the protocol handling for file data chunks

## Manual Testing

For more interactive testing, you can:

1. Run the full Python peer implementation:
   ```bash
   cd ../python_peer2
   python main.py
   ```

2. Run the Ruby peer in another terminal:
   ```bash
   cd ruby_peer2
   ruby main.rb
   ```

3. Use the interactive menus to establish connections, exchange keys, and transfer files between the implementations.

This can help with investigating specific interoperability issues that are hard to reproduce in automated tests. 