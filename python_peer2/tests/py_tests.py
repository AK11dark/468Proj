import sys
import os
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client import perform_key_exchange_with_ruby, request_file
from identity import sign_session_key, send_identity_to_ruby
from discover import discover_peers


def get_ruby_peer():
    peers = discover_peers()
    for peer in peers:
        if str(peer["port"]) == "5001":
            return peer
    return None




def test_mutual_auth_success():
    print("🔐 Testing mutual authentication success")
    peer = get_ruby_peer()
    if not peer:
        print("❌ Ruby peer not found")
        return False

    session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
    if not session_key:
        return False

    payload = sign_session_key(session_key)
    return send_identity_to_ruby(peer["ip"], peer["port"], payload)


def test_mutual_auth_failure_tampered_signature():
    print("🔐 Testing mutual authentication failure with tampered signature")
    peer = get_ruby_peer()
    if not peer:
        return False

    session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
    payload = sign_session_key(session_key)

    # Tamper with signature
    bad_sig = bytearray.fromhex(payload["signature"])
    bad_sig[0] ^= 0xFF
    payload["signature"] = bad_sig.hex()

    return not send_identity_to_ruby(peer["ip"], peer["port"], payload)


def test_auth_key_mismatch():
    print("🔐 Testing key mismatch rejection")
    peer = get_ruby_peer()
    if not peer:
        return False

    session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
    payload = sign_session_key(session_key)
    payload["public_key"] = payload["public_key"].replace("A", "B", 1)

    return not send_identity_to_ruby(peer["ip"], peer["port"], payload)


def test_file_list_request():
    print("📄 Testing file list request")
    peer = get_ruby_peer()
    if not peer:
        return False

    try:
        from client import request_file_list
        files = request_file_list(peer["ip"], peer["port"])
        print("Files shared by peer:", files)
        return isinstance(files, list)
    except Exception as e:
        print("❌ File list request failed:", e)
        return False


def test_request_nonexistent_file():
    print("📄 Testing request for non-existent file")
    peer = get_ruby_peer()
    if not peer:
        return False

    session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
    payload = sign_session_key(session_key)
    send_identity_to_ruby(peer["ip"], peer["port"], payload)

    # No exception = pass
    try:
        request_file(peer["ip"], peer["port"], "this_file_does_not_exist.txt", session_key)
        return True
    except:
        return False


def test_tampered_file():
    print("🧨 Testing decryption failure from tampered file")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from encryption_utils import encrypt_file

    peer = get_ruby_peer()
    if not peer:
        return False

    session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])

    file_path = os.path.join(os.path.dirname(__file__), "..", "Files", "hello.txt")
    if not os.path.exists(file_path):
        print("❌ Test file 'hello.txt' not found in Files/")
        return False

    with open(file_path, "rb") as f:
        content = f.read()

    encrypted = encrypt_file(content, session_key)
    tampered_ct = encrypted["ciphertext"][:-1] + b"\x00"

    try:
        decryptor = Cipher(
            algorithms.AES(session_key),
            modes.GCM(encrypted["iv"], encrypted["tag"])
        ).decryptor()
        decryptor.update(tampered_ct) + decryptor.finalize()
        return False  # Should fail
    except:
        return True


def test_forward_secrecy():
    print("🔁 Testing perfect forward secrecy (ephemeral keys)")
    peer = get_ruby_peer()
    if not peer:
        return False

    k1 = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
    k2 = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
    return k1 != k2


# --- MAIN RUNNER --- #

if __name__ == "__main__":
    tests = [
        ("Mutual Auth Success", test_mutual_auth_success),
        ("Tampered Signature Rejected", test_mutual_auth_failure_tampered_signature),
        ("Key Mismatch Rejected", test_auth_key_mismatch),
        ("File List Request", test_file_list_request),
        ("Nonexistent File Request", test_request_nonexistent_file),
        ("Tampered File Decryption Fails", test_tampered_file),
        ("Perfect Forward Secrecy", test_forward_secrecy),
    ]

    passed = 0
    failed = 0

    print("\n🧪 Starting P2P Secure File Sharing Tests")

    for name, func in tests:
        try:
            result = func()
            if result:
                print(f"✅ {name}")
                passed += 1
            else:
                print(f"❌ {name}")
                failed += 1
        except Exception as e:
            print(f"❌ {name} - EXCEPTION")
            traceback.print_exc()
            failed += 1

    print("\n📊 Test Summary:")
    print(f"   ✅ Passed: {passed}")
    print(f"   ❌ Failed: {failed}")
