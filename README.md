Basic usage:

1. Open 2 terminals, cd one of them to python_peer2 and the other to ruby_peer2
2. Upon first startup, you need to create an identity, this shares a username and ECDSA public key which the other client will keep track of in the future.
(Ensure who you think is sending the first file request is actually them by contacting them outside of the P2P module, as it uses Trust on First Use.)
3. Once you create an identity, you can send a file request which will save you as a contact.
4. 

Criteria Satisfaction:

2. Mutual Auth
🔐 test_mutual_auth_success: Performs a full key exchange, signs a session key with the user's ECDSA key, and sends it to the Ruby peer for verification. A successful response confirms the peer trusts the signature.
🔐 test_mutual_auth_failure_tampered_signature: Simulates an attack by modifying the signature before sending. The peer correctly rejects the signature.
🔏 test_auth_key_mismatch: Replaces the public key with a tampered one while keeping the username the same. The Ruby peer rejects this mismatch to prevent impersonation.

4. Request File List
📄 test_file_list_request: Sends a list request using command L. The peer responds with a JSON list of filenames, no approval required.

5. File Integrity
🧨 test_tampered_file: Encrypts a file with AES-GCM, then modifies one byte of the ciphertext. The decryption fails with an exception, proving that any tampering is detected.

7. File Integrity
🔐 test_mutual_auth_success and test_tampered_file indirectly validate this.
Files are encrypted using AES-GCM with ephemeral session keys (see requirement 8).

8. Perfect Forward Secrecy

🔁 test_forward_secrecy: Performs two key exchanges in a row and verifies the derived session keys are different.

10. Security Failures and Errors
❌ test_mutual_auth_failure_tampered_signature: Prints a clear error when signature verification fails.
❌ test_auth_key_mismatch: Prints a warning when a public key doesn’t match a known identity.

