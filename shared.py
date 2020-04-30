from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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

def construct_msg(ver, seq_num, cmd, recipient_pub_key, add_info="", file=""):
    print('Constructing a message.')


    
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                             Key Storage & Loading
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


# IN: pubkey (RSA type), pubkeyfile (string)
# OUT: None
# DESC: Writes the passed public key to the passed file.    
def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))


# IN: pubkeyfile (string)
# OUT: None
# DESC: Attempts to load a key public key based on pubkeyfile. Prints error if unable to do so.
def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)


# IN: keypair (RSA type), privkeyfile (string)
# OUT: None
# DESC: Writes the passed keypair to the passed file.
def save_keypair(keypair, privkeyfile):
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM'))

# IN: privkeyfile (string)
# OUT: None
# DESC: Attempts to load a key pair based on privkeyfile. Prints error if unable to do so.
def load_keypair(privkeyfile):
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)
