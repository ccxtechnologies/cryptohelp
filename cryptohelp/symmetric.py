# Copyright: 2018, CCX Technologies

import nacl.secret
import nacl.utils
import hashlib
import binascii
import os

_file_version = b'v001'


def create_key() -> bytes:
    """Create a key suitable for use with these symmetric crypto tools.

    Returns:
        A random key which can be used by the symmetric crypto tools
        in this module (bytes).
    """

    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)


def encrypt(key: bytes, message: bytes):
    """Encrypt a message using NaCl and a symmetric key.

    Args:
        key (bytes): key created by create_key()
        message (str): message to encrypt

    Returns:
        An encrypted message (bytes).
    """

    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return box.encrypt(message, nonce)


def decrypt(key: bytes, message: bytes):
    """Decrypt a message using NaCl and a symmetric key.

    Args:
        key (bytes): key created by create_key()
        message (str): message to decrypt

    Returns:
        An decrypted message (bytes).
    """

    box = nacl.secret.SecretBox(key)
    return box.decrypt(message)


def encrypt_file(key: bytes, plain_file: str, encrypted_file: str):
    """Encrypt a file using NaCl and a symmetric key, can be used on large files.

    Args:
        key (bytes): key created by create_key()
        plain_file (str): path / name of the file to encrypt
        encrypted_file (str): path / name of the encrypted file to create
    """

    sha256 = hashlib.sha256()

    with open(plain_file, 'rb') as fi:
        while True:
            chunk = fi.read(16384)
            if chunk:
                sha256.update(chunk)
            else:
                break
    checksum = sha256.digest()

    box = nacl.secret.SecretBox(key)

    with open(encrypted_file, 'wb') as fo, open(plain_file, 'rb') as fi:

        # 16384 - 4 (file version) - 32 (checksum) - 40 (NaCl adds 40)
        chunk = fi.read(16308)

        chunk = _file_version + checksum + chunk

        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = box.encrypt(chunk, nonce)
        fo.write(enc)

        while chunk:
            chunk = fi.read(16344)  # 16384 - 40 (NaCl adds 40 bytes)
            nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

            if chunk:
                enc = box.encrypt(chunk, nonce)
                fo.write(enc)


def decrypt_file(key: bytes, encrypted_file: str, plain_file: str):
    """Decrypt a file using NaCl and a symmetric key, can be used on large files.

    Args:
        key (bytes): key created by create_key()
        encrypted_file (str): path / name of the file to encrypted file to read
        plain_file (str): path / name of the decrypted file to create
    """

    box = nacl.secret.SecretBox(key)

    checksum = None
    sha256 = hashlib.sha256()

    with open(plain_file, 'wb') as fo, open(encrypted_file, 'rb') as fi:
        while True:
            chunk = fi.read(16384)
            if not chunk:
                break

            dec = box.decrypt(chunk)

            if not checksum:
                version = dec[:4]
                checksum = dec[4:36]
                dec = dec[36:]

            sha256.update(dec)
            fo.write(dec)

    if version != _file_version:
        os.remove(plain_file)
        raise RuntimeError("Bad File-Type")

    if checksum != sha256.digest():
        os.remove(plain_file)
        raise RuntimeError("Bad Checksum")
