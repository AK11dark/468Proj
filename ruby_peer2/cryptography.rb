require 'openssl'
require 'base64'

# Ensure compatibility with Python cryptography library
# Both implementations must use the same curve: secp256r1 (prime256v1)
class Cryptography
  CURVE_NAME = 'prime256v1' # This is the Ruby name for secp256r1

  # Generate an EC key pair using the proper curve
  def self.generate_key
    OpenSSL::PKey::EC.generate(CURVE_NAME)
  end

  # Sign data using the private key
  # Compatible with Python's ec.ECDSA(hashes.SHA256())
  def self.sign(private_key, data)
    digest = OpenSSL::Digest::SHA256.digest(data)
    private_key.dsa_sign_asn1(digest)
  end

  # Verify signature using a public key
  # Compatible with Python's verify(signature, data, ec.ECDSA(hashes.SHA256()))
  def self.verify(public_key, data, signature)
    digest = OpenSSL::Digest::SHA256.digest(data)
    public_key.dsa_verify_asn1(digest, signature)
  end

  # Convert public key to PEM format
  def self.public_key_to_pem(key)
    pub = OpenSSL::PKey::EC.new(CURVE_NAME)
    pub.public_key = key.public_key
    pub.to_pem
  end
end
