#!/usr/bin/env python3
# encoding: UTF-8
# Swopnil N. Shrestha
# 2020/04/16

from socket import socket, gethostname
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from typing import Tuple, Dict
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, DES, Blowfish
from diffiehellman.diffiehellman import DiffieHellman

HOST = gethostname()
PORT = 4600
SUPPORTED_CIPHERS = {"DES": [56]}


def parse_proposal(msg: str) -> Dict[str, list]:
    """Parse client's proposal

    :param msg: message from the client with a proposal (ciphers and key sizes)
    :return: the ciphers and keys as a dictionary
    """
    msg = msg[16:]
    ciphers = {}
    last_c = ''
    cipher_name = ''
    key_size = ''
    curr_key_size_list = []

    for c in msg:
        if c.isalpha():
            cipher_name += c
        elif c.isalnum():
            key_size += c
        elif c in ',':
            if last_c.isalnum():
                curr_key_size_list.append(int(key_size))
                key_size = ''
        elif c == ']':
            curr_key_size_list.append(int(key_size))
            key_size = ''
            ciphers[cipher_name] = curr_key_size_list
            cipher_name = ''
            curr_key_size_list = []
        last_c = c

    return ciphers


def select_cipher(supported: dict, proposed: dict) -> Tuple[str, int]:
    """Select a cipher to use

    :param supported: dictionary of ciphers supported by the server
    :param proposed: dictionary of ciphers proposed by the client
    :return: tuple (cipher, key_size) of the common cipher where key_size is the longest supported by both
    :raise: ValueError if there is no (cipher, key_size) combination that both client and server support
    """

    common_ciphers = set(supported.keys()).intersection(proposed.keys())

    cipher = None
    key_size = -1

    if common_ciphers != set():
        for c in common_ciphers:
            current_keysize = max(
                # -1 will be the max value if the intersection is empty
                set([-1]).union(set(supported.get(c)).intersection(proposed.get(c))))
            if current_keysize > key_size:
                key_size = current_keysize
                cipher = c

    if not cipher or key_size == -1:
        raise ValueError(
            'Could not agree on a cipher')

    return (cipher, key_size)


def generate_cipher_response(cipher: str, key_size: int) -> str:
    """Generate a response message

    :param cipher: chosen cipher
    :param key_size: chosen key size
    :return: (cipher, key_size) selection as a string
    """
    return "ChosenCipher:{},{}".format(cipher, key_size)


def parse_dhm_request(msg: str) -> int:
    """Parse client's DHM key exchange request

    :param msg: client's DHMKE initial message
    :return: number in the client's message
    """
    return int(msg.split(':')[1])


def get_key_and_iv(
    shared_key: str, cipher_name: str, key_size: int
) -> Tuple[object, bytes, bytes]:
    """Get key and IV from the generated shared secret key

    :param shared_key: shared key as computed by `diffiehellman`
    :param cipher_name: negotiated cipher's name
    :param key_size: negotiated key size
    :return: (cipher, key, IV) tuple
    cipher_name must be mapped to a Crypto.Cipher object
    `key` is the *first* `key_size` bytes of the `shared_key`
    DES key must be padded to 64 bits with 0
    Length `ivlen` of IV depends on a cipher
    `iv` is the *last* `ivlen` bytes of the shared key
    Both key and IV must be returned as bytes
    """
    cipher_map = {
        "DES": DES, "AES": AES, "Blowfish": Blowfish
    }

    ivlen = {
        "DES": 8, "AES": 16, "Blowfish": 8
    }

    cipher = cipher_map.get(cipher_name)
    key = shared_key[:key_size//8]
    if cipher_name == "DES":
        key += '\0'
    key = key.encode()
    iv = shared_key[-1 * ivlen.get(cipher_name):].encode()

    return cipher, key, iv


def generate_dhm_response(public_key: int) -> str:
    """Generate DHM key exchange response

    :param public_key: public portion of the DHMKE
    :return: string according to the specification
    """
    return 'DHMKE:{}'.format(public_key)


def read_message(msg_cipher: bytes, crypto: object) -> Tuple[str, str]:
    """Read the incoming encrypted message

    :param msg_cipher: encrypted message from the socket
    :crypto: chosen cipher, must be initialized in the `main`
    :return: (plaintext, hmac) tuple
    """

    ciph_in = msg_cipher[:-64]
    hmac = msg_cipher[-64:].decode('utf-8')
    plaintext = crypto.decrypt(ciph_in).decode('utf-8')
    plaintext = plaintext.strip('\0')
    return plaintext, hmac


def validate_hmac(msg_cipher: bytes, hmac_in: str, hashing: object) -> bool:
    """Validate HMAC

    :param msg_cipher: encrypted message from the socket
    :param hmac_in: HMAC received from the client
    :param hashing: hashing object, must be initialized in the `main`
    :raise: ValueError is HMAC is invalid
    """
    ciphertext = msg_cipher[:-64]
    hashing.update(ciphertext)
    hashvalue = hashing.hexdigest()

    if hashvalue == hmac_in:
        return True
    else:
        raise ValueError('Bad HMAC')


def main():
    """Main loop

    See vpn.md for details
    """
    # Create the socket
    server_sckt = socket(AF_INET, SOCK_STREAM)
    server_sckt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_sckt.bind((HOST, PORT))
    server_sckt.listen()
    print(f"Listening on {HOST}:{PORT}")
    conn, client = server_sckt.accept()
    print(f"New client: {client[0]}:{client[1]}")

    # Negotiating the cipher
    print("Negotiating the cipher")
    msg_in = conn.recv(4096).decode('utf-8')
    proposed = parse_proposal(msg_in)
    cipher_name, key_size = select_cipher(SUPPORTED_CIPHERS, proposed)
    print(f"We are going to use {cipher_name}{key_size}")
    msg_out = generate_cipher_response(cipher_name, key_size)
    conn.send(msg_out.encode())

    # Negotiating the key
    print("Negotiating the key")
    dh = DiffieHellman()
    dh.generate_public_key()
    msg_in = conn.recv(4096).decode('utf-8')
    client_public_key = parse_dhm_request(msg_in)
    dh.generate_shared_secret(client_public_key)
    msg_out = generate_dhm_response(dh.public_key)
    conn.send(msg_out.encode())
    cipher, key, iv = get_key_and_iv(dh.shared_key, cipher_name, key_size)
    print("The key has been established")

    print("Initializing cryptosystem")
    crypto = cipher.new(key, cipher.MODE_CBC, iv)
    hashing = HMAC.new(key, digestmod=SHA256)
    print("All systems ready")

    while True:
        msg_in = conn.recv(4096)
        if len(msg_in) < 1:
            conn.close()
            break
        msg, hmac = read_message(msg_in, crypto)
        validate_hmac(msg_in, hmac, hashing)
        print(f"Received: {msg}")
        msg_out = f"Server says: {msg[::-1]}"
        conn.send(msg_out.encode())


if __name__ == "__main__":
    main()
