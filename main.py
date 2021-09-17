from os import mkdir
from os import path as ospath

from ecdsa import SigningKey, SECP256k1
from subprocess import check_output, STDOUT
from pyasn1.codec.der import decoder
from binascii import a2b_hex, b2a_hex
from hashlib import new, sha256
from base58 import b58encode, b58decode
from pybitcointools import sign

import json
import httplib2
import os

DATA = os.path.join(os.path.expanduser('~'), 'data')
mkdir(DATA)

def change_endianness(x):
    # If there is an odd number of elements, we make it even by adding a 0
    if (len(x) % 2) == 1:
        x += "0"
    y = x.decode('hex')
    z = y[::-1]
    return z.encode('hex')

def decode_varint(varint):
    if len(varint) > 2:
        decoded_varint = int(change_endianness(varint[2:]), 16)
    else:
        decoded_varint = int(varint, 16)

    return decoded_varint

def int2bytes(a, b):
    return ('%0' + str(2 * b) + 'x') % a


class TX:

    def __init__(self, version=None, inputs=None, prev_tx_id=None, prev_out_index=None, scriptSig_len=None, scriptSig=None,
                 nSequence=None, outputs=None, value=None, scriptPubKey_len=None, scriptPubKey=None, nLockTime=None):
        if prev_tx_id is None:
            prev_tx_id = []
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.nLockTime = nLockTime

        if prev_tx_id is None:
            self.prev_tx_id = []
        else:
            self.prev_tx_id = prev_tx_id

        if prev_out_index is None:
            self.prev_out_index = []
        else:
            self.prev_out_index = prev_out_index

        if scriptSig is None:
            self.scriptSig = []
        else:
            self.scriptSig = scriptSig

        if scriptSig_len is None:
            self.scriptSig_len = []
        else:
            self.scriptSig_len = scriptSig_len

        if nSequence is None:
            self.nSequence = []
        else:
            self.nSequence = nSequence

        if value is None:
            self.value = []
        else:
            self.value = value

        if scriptPubKey is None:
            self.scriptPubKey = []
        else:
            self.scriptPubKey = scriptPubKey

        if scriptPubKey_len is None:
            self.scriptPubKey_len = []
        else:
            self.scriptPubKey_len = scriptPubKey_len

        self.hex = None
        self.offset = 0

    def to_hex(self):
        if self.hex is None:
            self.hex = self.version + self.inputs

            for i in range(len(self.prev_tx_id)):
                self.hex += self.prev_tx_id[i] + self.prev_out_index[i] + self.scriptSig_len[i] \
                            + self.scriptSig[i] + self.nSequence[i]

            self.hex += self.outputs

            for i in range(len(self.scriptPubKey)):
                self.hex += self.value[i] + self.scriptPubKey_len[i] + self.scriptPubKey[i]

            self.hex += self.nLockTime

        return self.hex

    def build_default_tx(self, prev_tx_id, prev_out_index, value, scriptPubKey, scriptSig=None):

        self.version = "01000000"

        n_inputs = len(prev_tx_id)
        self.inputs = int2bytes(n_inputs, 1)

        for i in range(n_inputs):
            self.prev_tx_id.append(change_endianness(prev_tx_id[i]))
            self.prev_out_index.append(change_endianness(int2bytes(prev_out_index[i], 4)))

        for i in range(n_inputs):
            if scriptSig is None:
                self.scriptSig.append("0")
                self.scriptSig_len.append("0")

            else:
                self.scriptSig_len.append(int2bytes(len(scriptSig[i]) / 2, 1))

            self.nSequence.append("ffffffff")

        n_outputs = len(scriptPubKey)
        self.outputs = int2bytes(n_outputs, 1)

        for i in range(n_outputs):
            self.value.append(change_endianness(int2bytes(value[i], 8)))

            self.scriptPubKey_len.append(int2bytes(len(scriptPubKey[i]) / 2, 1))
            self.scriptPubKey = scriptPubKey

        self.nLockTime = "00000000"

        self.to_hex()


def hash_160(pk):
    """ Calculates the RIPEMD-160 hash of a given elliptic curve key.

    :param pk: elliptic curve public key (in hexadecimal format).
    :type pk: hex str
    :return: The RIPEMD-160 hash.
    :rtype: bytes
    """

    # Calculate the RIPEMD-160 hash of the given public key.
    md = new('ripemd160')
    h = sha256(a2b_hex(pk)).digest()
    md.update(h)
    h160 = md.digest()

    return h160


def hash_160_to_btc_address(h160, v):
    """ Calculates the Bitcoin address of a given RIPEMD-160 hash from an elliptic curve public key.

    :param h160: RIPEMD-160 hash.
    :type h160: bytes
    :param v: version (prefix) used to calculate the Bitcoin address.

     Possible values:

        - 0 for main network (PUBKEY_HASH).
        - 111 For testnet (TESTNET_PUBKEY_HASH).
    :type v: int
    :return: The corresponding Bitcoin address.
    :rtype: hex str
    """

    # Add the network version leading the previously calculated RIPEMD-160 hash.
    vh160 = chr(v) + h160
    # Double sha256.
    h = sha256(sha256(vh160).digest()).digest()
    # Add the two first bytes of the result as a checksum tailing the RIPEMD-160 hash.
    addr = vh160 + h[0:4]
    # Obtain the Bitcoin address by Base58 encoding the result
    addr = b58encode(addr)

    return addr


def btc_address_to_hash_160(btc_addr):
    """ Calculates the RIPEMD-160 hash from a given Bitcoin address

    :param btc_addr: Bitcoin address.
    :type btc_addr: str
    :return: The corresponding RIPEMD-160 hash.
    :rtype: hex str
    """

    # Base 58 decode the Bitcoin address.
    decoded_addr = b58decode(btc_addr)
    # Covert the address from bytes to hex.
    decoded_addr_hex = b2a_hex(decoded_addr)
    # Obtain the RIPEMD-160 hash by removing the first and four last bytes of the decoded address, corresponding to
    # the network version and the checksum of the address.
    h160 = decoded_addr_hex[2:-8]

    return h160


def public_key_to_btc_address(pk, v='main'):
    """ Calculates the Bitcoin address of a given elliptic curve public key.

    :param pk: elliptic curve public key.
    :type pk: hex str
    :param v: version used to calculate the Bitcoin address.
    :type v: str
    :return: The corresponding Bitcoin address.

        - main network address if v is 'main.
        - testnet address otherwise
    :rtype: hex str
    """

    PUBKEY_HASH = 0
    TESTNET_PUBKEY_HASH = 111

    # Choose the proper version depending on the provided 'v'.
    if v is 'main':
        v = PUBKEY_HASH
    elif v is 'test':
        v = TESTNET_PUBKEY_HASH
    else:
        raise Exception("Invalid version, use either 'main' or 'test'.")

    # Calculate the RIPEMD-160 hash of the given public key.
    h160 = hash_160(pk)
    # Calculate the Bitcoin address from the chosen network.
    btc_addr = hash_160_to_btc_address(h160, v)

    return btc_addr


def generate_btc_addr(pk, v='main'):
    """ Calculates Bitcoin address associated to a given elliptic curve public key and a given network.

    :param pk: elliptic curve public key (in hexadecimal format).
    :type pk: EC_pub
    :param v: version (prefix) used to calculate the WIF, it depends on the type of network.
    :type v: str
    :return: The Bitcoin address associated to the given public key and network.
    :rtype: str
    """

    # Get the hex representation of the provided EC_pub.
    public_key_hex = get_pub_key_hex(pk)
    # Generate the Bitcoin address of de desired network.
    btc_addr = public_key_to_btc_address(public_key_hex, v)

    return btc_addr


def generate_keys():
    """ Gets a new  elliptic curve key pair using the SECP256K1 elliptic curve (the one used by Bitcoin).

    :return: elliptic curve key pair.
    :rtype: list
    """

    # Generate the key pair from a SECP256K1 elliptic curve.
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key()

    return sk, pk


def get_priv_key_hex(sk_file_path):
    """ Gets the EC private key in hexadecimal format from a key file.

    :param sk_file_path: system path where the EC private key is found.
    :type sk_file_path: str
    :return: private key.
    :rtype: hex str
    """

    # Obtain the private key using an OpenSSL system call.
    cmd = ['openssl', 'ec', '-in', sk_file_path, '-text', '-noout']

    response = check_output(cmd, stderr=STDOUT)
    # Parse the result to remove all the undesired spacing characters.
    raw_key = response[response.find('priv:') + 8: response.find('pub:')]
    raw_key = raw_key.replace(":", "")
    raw_key = raw_key.replace(" ", "")
    raw_key = raw_key.replace("\n", "")

    # If the key starts with 00, the two first characters are removed.
    if raw_key[:2] == '00':
        sk_hex = raw_key[2:]
    else:
        sk_hex = raw_key

    return sk_hex


def get_pub_key_hex(pk_der):
    """ Converts a public key in hexadecimal format from a DER encoded public key.

    :param pk_der: DER encoded public key
    :type pk_der: bytes
    :return: public key.
    :rtype: hex str
    """

    # Get the asn1 representation of the public key DER data.
    asn1_pk, _ = decoder.decode(str(pk_der))

    # Get the public key as a BitString. The public key corresponds to the second component
    # of the asn1 public key structure.
    pk_bit = asn1_pk.getComponentByPosition(1)

    # Convert the BitString into a String.
    pk_str = ""
    for i in range(len(pk_bit)):
        pk_str += str(pk_bit[i])

    # Parse the data to get it in the desired form.
    pk_hex = '0' + hex(int(pk_str, 2))[2:-1]

    return pk_hex


def generate_std_scriptpubkey(target_btc_addr):

    OP_DUP = 118
    OP_HASH_160 = 169
    OP_EQUALVERIFY = 136
    OP_CHECKSIG = 172

    h160 = btc_address_to_hash_160(target_btc_addr)

    scriptpubkey = format(OP_DUP, 'x') + format(OP_HASH_160, 'x') + format(int(len(h160) / 2), 'x') + h160 + \
                   format(OP_EQUALVERIFY, 'x') + format(OP_CHECKSIG, 'x')

    # scriptpubkey = '{:02x}'.format(OP_DUP) + '{:02x}'.format(OP_HASH_160) + '{:02x}'.format(int(len(h160)/2)) + h160 + '{:02x}'.format(OP_EQUALVERIFY) + '{:02x}'.format(OP_CHECKSIG)
    return scriptpubkey


def build_raw_tx(prev_tx_id, prev_out_index, value, src_btc_addr, dest_btc_addr):

    assert len(prev_tx_id) == len(prev_out_index) == len(value) == len(src_btc_addr)

    scriptPubKey = []
    for i in range(len(dest_btc_addr)):
        scriptPubKey.append(generate_std_scriptpubkey(dest_btc_addr[i]))

    tx = TX()
    tx.build_default_tx(prev_tx_id, prev_out_index, value, scriptPubKey)

    signed_tx = ""
    for i in range(len(src_btc_addr)):
        pirv_key = DATA + "/" + src_btc_addr[i] + "/sk.pem"
        priv_key_hex = get_priv_key_hex(pirv_key)
        signed_tx = sign(tx.hex, 0, priv_key_hex)

    return signed_tx

# Create key pair
#
# Function UAB_gen_and_store_keys().
# 

def UAB_gen_and_store_keys():
    
    # Both the public and private key are stored in disk. The Bitcoin address is used as an identifier in the name
    # of the file.
    def store_keys(sk, pk, btc_addr):
        """ Stores an elliptic curve key pair in PEM format into disk.
    
        :param sk: PEM encoded elliptic curve private key.
        :type sk: str
        :param pk: PEM encoded elliptic curve public key.
        :type pk: str
        :param btc_addr: Bitcoin address associated to the public key of the key pair.
        :type btc_addr: str
        :return: None.
        :rtype: None
        """
        
        btc_path = DATA + "/" + btc_addr
        mkdir(btc_path)
    
        sk_path=btc_path + "/" + "sk.pem"
        pk_path=btc_path + "/" + "pk.pem"
        open(sk_path, "w").write(sk)
        open(pk_path, "w").write(pk)
        
        
        
    # Generate the elliptic curve keys.
    sk, pk = generate_keys()
    
    #Generate the bitcoin address from the public key.
    v='test'
    btc_addr = generate_btc_addr(pk.to_der(),v)
        
    print(btc_addr)
    
    #Store the keys to disk.    
    store_keys(sk.to_pem(), pk.to_pem(), btc_addr)
    return btc_addr
        
    ##################################  
UAB_gen_and_store_keys()



# Generate here at least two key pairs using UAB_gen_and_store_keys()

def mostra(btc_addr):
    
    btc_path = DATA + "/" + str(btc_addr)
    
    sk_path=btc_path + "/" + "sk.pem"
    sk = open(sk_path, 'r')
    print(sk.read())
    sk.close()
    
    pk_path=btc_path + "/" + "pk.pem"
    pk = open(pk_path, 'r')
    print(pk.read())
    pk.close()

#### INCLUDE THE REQUIRED INFORMATION ####

# Address 1: 
addr1 = UAB_gen_and_store_keys()
mostra(addr1)
# Address 2:
addr2 = UAB_gen_and_store_keys()
mostra(addr2)

##################################


# Create a standard transaction
#


# Amount to be spent, in Satoshis.
value = [10000] # 0.0001 BTC 

# Bitcoin address where the bitcoins come from. It should match with the address referenced by the prev_tx_id.

src_btc_addr = ['mwYEEfNopboQMJQU6JB9J2EtLXRwTzy7gQ'] 

prev_tx_id = ['b9a836a6bcbf7e2ccb702f1b79d5dab4403007087d85d7f2854f68a310e91629']

# The address will be used as an identifier to choose the proper keys when signing the
# transaction. The address should exist in the wallet



# Destination Bitcoin address, where the value in bitcoins will be sent

dest_btc_addr = ['mfXUi2XGsaG7NiWyjLPuzrUgoDTZ9Z725Y']

# Build the raw transaction using all the provided inputs.
prev_out_index = [0]

transaccion = build_raw_tx(prev_tx_id, prev_out_index, value, src_btc_addr, dest_btc_addr)

print(transaccion)


# The transaction in JSON  format
#
"""
{
    "addresses": [
        "mwYEEfNopboQMJQU6JB9J2EtLXRwTzy7gQ", 
        "mfXUi2XGsaG7NiWyjLPuzrUgoDTZ9Z725Y"
    ], 
    "block_height": -1, 
    "block_index": -1, 
    "confirmations": 0, 
    "double_spend": false, 
    "fees": 290000, 
    "hash": "5c9e95fa50b61521038bc2400974f6c2bd6ed2e280c89a78239f93e8a47e9872", 
    "inputs": [
        {
            "addresses": [
                "mwYEEfNopboQMJQU6JB9J2EtLXRwTzy7gQ"
            ], 
            "age": 0, 
            "output_index": 0, 
            "output_value": 300000, 
            "prev_hash": "b9a836a6bcbf7e2ccb702f1b79d5dab4403007087d85d7f2854f68a310e91629", 
            "script": "48304502210082af86bba375368477512b4cca35451f92afa85c5fe9fd78ad843043e954a22002205700bb5e2b044e9286dca76dee491ace1759e06d0bc88cc0986dac20967f5a460141041e144ccf05cac596fb4c5b93999469b3aefc833cce81ef515e4e92588b405a269573e00c56a0b58cf1f1f1e700b87dfe59d780b6d4613f32254a387f5f261c58", 
            "script_type": "pay-to-pubkey-hash", 
            "sequence": 4294967295
        }
    ], 
    "outputs": [
        {
            "addresses": [
                "mfXUi2XGsaG7NiWyjLPuzrUgoDTZ9Z725Y"
            ], 
            "script": "76a91400196344c15b4a0a3edce8ed8416f847d36c219e88ac", 
            "script_type": "pay-to-pubkey-hash", 
            "value": 10000
        }
    ], 
    "preference": "high", 
    "received": "2019-12-19T10:06:37.471848147Z", 
    "relayed_by": "3.91.85.252", 
    "size": 224, 
    "total": 10000, 
    "ver": 1, 
    "vin_sz": 1, 
    "vout_sz": 1
}

"""


# Compute balance of a single address
#
def UAB_get_balance(addr):
    
    amount = -1
    
    #### IMPLEMENTATION GOES HERE ####

    addr_info = 'https://api.blockcypher.com/v1/btc/test3/addrs/' + addr + '/balance'

    request, content = httplib2.Http().request(addr_info)
    data=json.loads(content)
    amount = data['final_balance']
    ##################################
    
    return amount

# Use UAB_get_balance() to compute the balance of some of your addresses

balance=UAB_get_balance('mfXUi2XGsaG7NiWyjLPuzrUgoDTZ9Z725Y')
print(balance)


# Compute total balance of a wallet
#

def UAB_get_total_balance():
    
    total_balance=0
    
    for addr in os.listdir(DATA):
        
        if addr.startswith("m"):
            total_balance += UAB_get_balance(addr)
    
    return total_balance


# Use UAB_get_total_balance() to compute the total balance of your wallet

total = UAB_get_total_balance()
print(total)