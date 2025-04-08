Basic usage:

1. Open code using github codespace and install necessary python packages. cryptography and zeroconf.
2. Ensure that identity.json, known_peers.json and ecdsa_key.pem all do not exist in both folders before starting
3. open 2 terminals, cd one of them to python_peer2 and the other to ruby_peer2
4. start python with python main.py
5. start ruby with ruby main.rb
6. Upon first startup, you need to create an identity, this shares a username and ECDSA public key which the other client will keep track of in the future.
(Ensure who you think is sending the first file request is actually them by contacting them outside of the P2P module, as it uses Trust on First Use.)
7. Once you create an identity, you can send a file request which will save you as a contact.


Criteria Satisfaction:
1. Peer Discovery
Support peer discovery on a local network (e.g., via mDNS).

Every test begins with a call to discover_peers(), which performs mDNS peer discovery. If no peers are found, the test exits early.

2. Mutual Auth
   
🔐 test_mutual_auth_success: Performs a full key exchange, signs a session key with the user's ECDSA key, and sends it to the Ruby peer for verification. A successful response confirms the peer trusts the signature.

🔐 test_mutual_auth_failure_tampered_signature: Simulates an attack by modifying the signature before sending. The peer correctly rejects the signature.

🔏 test_auth_key_mismatch: Replaces the public key with a tampered one while keeping the username the same. The Ruby peer rejects this mismatch to prevent impersonation.

3. File Request with Consent

The request_file() function triggers a prompt on the sender's console to confirm the file transfer. Although this is a manual confirmation, the system halts the transfer until the user responds.

4. Request File List

📄 test_file_list_request: Sends a list request using command L. The peer responds with a JSON list of filenames, no approval required

6. New key migration

The key migration implementation uses a cryptographic signature chain where a user's current private key signs their new public key

8. File Integrity
   
🧨 test_tampered_file: Encrypts a file with AES-GCM, then modifies one byte of the ciphertext. The decryption fails with an exception, proving that any tampering is detected.

🔐 test_mutual_auth_success and test_tampered_file indirectly validate this.


8. Perfect Forward Secrecy

🔁 test_forward_secrecy: Performs two key exchanges in a row and verifies the derived session keys are different.

10. Security Failures and Errors
❌ test_mutual_auth_failure_tampered_signature: Prints a clear error when signature verification fails.



POSSIBLE ISSUES:
IF you get an error such as [Python File Server] Server already running. Continuing with client mode only. you need to kill whatever is on port 5003 if python, and kill whatever is on port 5001 if ruby
IF you create an identity and then immedietly try to rotate it, it will not work, you MUST first request a file so the other client can save you

    


❌ test_auth_key_mismatch: Prints a warning when a public key doesn’t match a known identity.

