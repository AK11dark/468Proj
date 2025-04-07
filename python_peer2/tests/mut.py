import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client import perform_key_exchange_with_ruby
from identity import sign_session_key, send_identity_to_ruby
from discover import discover_peers

def test_mutual_auth_success():
    print("🔐 Running mutual authentication test...")

    peers = discover_peers()
    if not peers:
        print("❌ No peers found on the network.")
        return

    peer = peers[1]
    print(f"📡 Testing with peer: {peer['name']} @ {peer['ip']}:{peer['port']}")

    session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
    if not session_key:
        print("❌ Failed to perform key exchange.")
        return

    payload = sign_session_key(session_key)
    result = send_identity_to_ruby(peer["ip"], peer["port"], payload)

    if result:
        print("✅ Mutual authentication succeeded.")
    else:
        print("❌ Mutual authentication failed.")

def test_mutual_auth_failure_tampered_signature():
    print("\n🧪 Running tampered signature test...")

    peers = discover_peers()
    if not peers:
        print("❌ No peers found on the network.")
        return

    peer = peers[1]
    print(f"📡 Testing with peer: {peer['name']} @ {peer['ip']}:{peer['port']}")

    session_key = perform_key_exchange_with_ruby(peer["ip"], peer["port"])
    if not session_key:
        print("❌ Failed to perform key exchange.")
        return

    payload = sign_session_key(session_key)

    # 🔥 Tamper with signature (flip a byte)
    bad_sig = bytearray.fromhex(payload["signature"])
    bad_sig[0] ^= 0xFF  # flip first byte
    payload["signature"] = bad_sig.hex()

    result = send_identity_to_ruby(peer["ip"], peer["port"], payload)

    if not result:
        print("✅ Tampered signature correctly rejected.")
    else:
        print("❌ Tampered signature was wrongly accepted!")


if __name__ == "__main__":
    test_mutual_auth_success()
    test_mutual_auth_failure_tampered_signature()

