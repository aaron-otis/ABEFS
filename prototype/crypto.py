from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.core.engine.util import objectToBytes, bytesToObject
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from hashlib import sha256
import os

# Using abenc_waters09 and a hybrid encryption scheme to encrypt arbitrary data
# that is not a group element.
class ABECrypto:
    def __init__(self, group = "SS512"):
        self._group = PairingGroup(group)
        self._cpabe = CPabe09(self._group)
        self._hybrid_abe = HybridABEnc(self._cpabe, self._group)

        # TODO: Master keys should be generated once and stored securely 
        #       somewhere else.
        self._master_secret, self._master_public = self._cpabe.setup()

    # Generates a secret key for a user.
    def get_secret_key(self, attr_list):
        return self._cpabe.keygen(self._master_public, self._master_secret, attr_list)

    # Perform CP-ABE encryption.
    def _encrypt(self, g, policy):
        return self._cpabe.encrypt(self._master_public, g, policy)

    # Perform CP-ABE decryption.
    def _decrypt(self, key, c):
        return self._cpabe.decrypt(self._master_public, key, c)

    # Perform hybrid encryption.
    def encrypt(self, msg, cp_key, encrypted_aes_key, associated_data = None):
        try:
            g = self._decrypt(cp_key, encrypted_aes_key)
        except:
            print("[ERROR] Unable to decrypt AES key")
            return None

        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(sha256(self.toBytes(g)).digest()),
                           modes.GCM(iv),
                           backend = default_backend()).encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        c = encryptor.update(msg) + encryptor.finalize()
        return c, iv, encryptor.tag

    # Performs hybrid decryption.
    def decrypt(self, cp_key, encrypted_aes_key, ciphertext, iv, tag, associated_data = None):
        try:
            g = self._decrypt(cp_key, encrypted_aes_key)
        except:
            print("[ERROR] Unable to decrypt AES key")
            return None

        try:
            decryptor = Cipher(algorithms.AES(sha256(self.toBytes(g)).digest()),
                               modes.GCM(iv, tag),
                               backend = default_backend()).decryptor()
        except TypeError:
            return None

        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        try:
            msg = decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            print("[ERROR] Received invalid tag")
            return None

        return msg

    def toBytes(self, data):
        return objectToBytes(data, self._group)

    def fromBytes(self, data):
        return bytesToObject(data, self._group)

    # Derive a random group element g which will be hashed to become the symmetric key. 
    # Returns g encrypted via CP-ABE under the specified policy.
    def genAESKey(self, policy):
        g = self._group.random(GT)
        return self._encrypt(g, policy)

# main runs tests to ensure this package works as expected.
def main():
    abe = ABECrypto()

    # Policies and attribute list elements must be uppercase for some reason.
    policy = "(ME or YOU or 42 or GID1000 or GID0)"

    # Test several keys with different attributes.
    keys = [abe.get_secret_key(["ME"]), abe.get_secret_key(["YOU"]), 
            abe.get_secret_key(["YOU", "US"]), abe.get_secret_key(["US"]),
            abe.get_secret_key(["ME", "YOU"]), abe.get_secret_key(["42"]),
            abe.get_secret_key(["GID1000"]), abe.get_secret_key(["GID1"])]

    msg = b"a test message"
    c1 = abe.genAESKey(policy)
    ct, iv, tag = abe.encrypt(msg, keys[0], c1)

    for i, key in enumerate(keys):
        try:
            print("key {} decrypted to: {}".format(i, abe.decrypt(key, c1, ct, iv, tag)))
        except:
            print("key {} could not decrypt the ciphertext".format(i))

if __name__ == "__main__":
    main()
