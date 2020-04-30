from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS


CURRENT_VERSION = 0

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                            Encryption & Decryption
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


# IN: plaintext (bytestring), pub_key (RSA type)
# OUT: ciphertext (bytestring)
# DESC: Encrypts the plaintext with PKCS#1 OAEP (v1.5). Raises ValueError if the message is too long (>190 bytes)
# NOTE: You should call load_publickey and pass its result as the second parameter
def encrypt_with_RSA(plaintext, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    try:
        return cipher.encrypt(plaintext)
    except ValueError:
        print("Encryption ValueError: plaintext is too long (190 byte max)\nPlaintext: " + plaintext.decode('ascii'))
        sys.exit(1)
        

# IN: ciphertext (bytestring), priv_key (RSA type)
# OUT: plaintext (bytestring)
# DESC: Decrypts the plaintext with PKCS#1 OAEP (v1.5).
#       Raises ValueError if the ciphertext has the wrong length or if decryption fails the integrity check.
#       Raises TypeError if the RSA key has no private half (i.e. you are trying to decrypt using a pub key)
# NOTE: You should call load_keypair and pass its result as the second parameter
def decrypt_with_RSA(ciphertext, key_pair):
    cipher = PKCS1_OAEP.new(keypair)
    try:
        return cipher.decrypt(ciphertext)
    except ValueError:
        print("Decryption ValueError: either ciphertext has the wrong length or decryption failed the integrity check. Ensure you are using the correct key!")
        sys.exit(1)
    except TypeError:
        print("Decryption TypeError: the RSA key has no private half - you are trying to decrypt with a public key!")
        sys.exit(1)
        

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                    Misc
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


# IN: cmd (string)
# OUT: returns true if the command is a valid one, and false otherwise
def is_valid_cmd(cmd):
    return cmd.upper() in ["LGN", "MKD", "RMD", "GWD", "CWD", "LST", "UPL", "DNL", "RMF", "LGO"]

# IN: None
# OUT: version (Int)
# DESC: returns the current version number
def get_ver_num():
    return CURRENT_VERSION

    
def construct_msg(ver, seq_num, cmd, recipient_pub_key, add_info="", file=""):
    print('Constructing a message.')


    
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                             Key Storage & Loading
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


# IN: key (RSA/ECC type), privkeyfile (string)
# OUT: None
# DESC: Writes the passed keypair to the passed file.
# NOTE: key can either be a keypair or a publick key
def save_key(key, keyfile):
    f = open(keyfile, 'wb')
    f.write(key.export_key(format='PEM'))
    f.close()
    
# IN: keyfile (string)
# OUT: key (RSA type)
# DESC: Attempts to load a key from keyfile. Prints error if unable to do so.
# NOTE: Key can either be a public key or key pair
def load_RSA_key(keyfile):
    f = open(keyfile, 'rb')
    keystr = f.read()
    f.close()
    
    try:
        return RSA.import_key(keystr)
    except ValueError:
        print('Error: Cannot import key from file ' + keyfile)
        sys.exit(1)

        
# IN: keyfile (string)
# OUT: key (ECC type)
# DESC: Attempts to load a key from keyfile. Prints error if unable to do so.
# NOTE: Key can either be a public key or key pair
def load_ECC_key(keyfile):
    f = open(keyfile, 'rb')
    keystr = f.read()
    f.close()
    
    try:
        return ECC.import_key(keystr)
    except ValueError:
        print('Error: Cannot import key from file ' + keyfile)
        sys.exit(1)
