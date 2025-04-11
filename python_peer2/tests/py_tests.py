import sys
import os
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client import perform_key_exchange_with_ruby, request_file, request_file_list
from identity import sign_session_key, send_identity_to_ruby
from discover import discover_peers
from encryption_utils import encrypt_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from advertise import advertise_service, stop_advertisement
from auth_handler import save_known_peer, load_known_peers
from file_server import FileServer
from storage import SecureStorage


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



def test_advertise_service():
    print("📢 Testing service advertisement")
    try:
        name = advertise_service(name="test-peer", port=6000)
        assert name.startswith("test-peer")
        stop_advertisement()
        return True
    except Exception as e:
        print("❌ Advertise test failed:", e)
        return False


def test_known_peers_storage():
    print("🔒 Testing known peer storage and loading")
    try:
        test_key = "-----BEGIN PUBLIC KEY-----\nFAKEKEY\n-----END PUBLIC KEY-----"
        save_known_peer("testuser", test_key)
        peers = load_known_peers()
        assert peers["testuser"] == test_key
        return True
    except Exception as e:
        print("❌ Peer storage test failed:", e)
        return False


def test_file_server_hash_calc():
    print("🧮 Testing file hash calculation")
    try:
        test_path = "/tmp/testfile.txt"
        with open(test_path, "w") as f:
            f.write("test content")
        server = FileServer()
        h = server.calculate_file_hash(test_path)
        assert len(h) == 64  # SHA256 hash
        os.remove(test_path)
        return True
    except Exception as e:
        print("❌ Hash calculation test failed:", e)
        return False


def test_storage_encryption_decryption():
    print("📁 Testing file storage encryption and decryption")
    try:
        # Create test directory if it doesn't exist
        test_dir = "test_storage"
        os.makedirs(test_dir, exist_ok=True)
        
        content = b"secret test data"
        filename = "test_secret.txt"
        password = "strongpass"

        # Initialize storage with our test directory
        storage = SecureStorage(test_dir)
        
        # Store and encrypt the file
        enc_path = storage.store_encrypted_file(content, filename, password)
        print(f"Encrypted file path: {enc_path}")
        assert enc_path.endswith(".enc")
        assert os.path.exists(enc_path), f"Encrypted file {enc_path} does not exist"
        
        # Get the content back and decrypt it
        enc_filename = os.path.basename(enc_path)
        decrypted = storage.get_file_content(enc_filename, password)
        assert decrypted == content, "Decrypted content doesn't match original"

        # Cleanup
        if os.path.exists(enc_path):
            os.remove(enc_path)
        if os.path.exists(test_dir) and os.path.isdir(test_dir):
            os.rmdir(test_dir)
            
        return True
    except Exception as e:
        print("❌ Storage encryption test failed:", e)
        import traceback
        traceback.print_exc()
        
        # Cleanup in case of exception
        try:
            test_dir = "test_storage"
            temp_file = os.path.join(test_dir, "temp_test_secret.txt")
            enc_file = os.path.join(test_dir, "temp_test_secret.txt.enc")
            
            for f in [temp_file, enc_file]:
                if os.path.exists(f):
                    os.remove(f)
                    
            if os.path.exists(test_dir) and os.path.isdir(test_dir):
                os.rmdir(test_dir)
        except:
            pass
            
        return False

# --- MAIN RUNNER --- #

if __name__ == "__main__":
    tests = [
        ("Storage Encryption/Decryption", test_storage_encryption_decryption),
        ("File Server Hash Calculation", test_file_server_hash_calc),
        ("Known Peers Storage", test_known_peers_storage),
        ("Advertise Service", test_advertise_service),
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


# --- Additional Unit Tests --- #


