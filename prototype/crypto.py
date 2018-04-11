from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.adapters.abenc_adapt_hybrid import HybridABEnc

# Using abenc_waters09 and a hybrid encryption scheme to encrypt arbitrary data
# that is not a group element.
class ABECrypto:
    def __init__(self, group = "SS512"):
        self._group = PairingGroup(group)
        self._cpabe = CPabe09(self._group)
        self._hybrid_abe = HybridABEnc(self._cpabe, self._group)

        # TODO: Master keys should be generated once and stored securely 
        #       somewhere else.
        self._master_secret, self._master_public = self._hybrid_abe.setup()

    # Generates a secret key for a user.
    def get_secret_key(self, attr_list):
        return self._hybrid_abe.keygen(self._master_public, 
         self._master_secret, attr_list)

    # Performs hybrid encryption.
    def encrypt(self, msg, policy):
        return self._hybrid_abe.encrypt(self._master_public, msg, policy)

    # Performs hybrid decryption.
    def decrypt(self, key, ciphertext):
        return self._hybrid_abe.decrypt(self._master_public, key, ciphertext)

# main runs tests to ensure this package works as expected.
def main():
    abe = ABECrypto()

    # Policies and attribute list elements must be in uppercase for some 
    # reason.
    policy = "(ME or YOU)"

    # Test several keys with different attributes.
    keys = [abe.get_secret_key(["ME"]), abe.get_secret_key(["YOU"]), 
            abe.get_secret_key(["YOu", "US"]), abe.get_secret_key(["US"]),
            abe.get_secret_key(["ME", "YOU"])]

    msg = b"a test message"
    ct = abe.encrypt(msg, policy)

    for i, key in enumerate(keys):
        try:
            print("key {} decrypted to: {}".format(i, abe.decrypt(key, ct)))
        except:
            print("key {} could not decrypt the ciphertext".format(i))

if __name__ == "__main__":
    main()
