# Copyright: 2018, CCX Technologies

import os
import binascii
import nacl.public


def create_private_key_file(filename: str):
    """Create a private key suitable for use with these asymmetric crypto
        tools, and store it in a file.
    """

    with open(filename, 'wb') as fo:
        fo.write(nacl.public.PrivateKey.generate()._private_key)
    os.chmod(filename, 0o600)


def get_public_key(private_key: bytes) -> str:
    """Get the public key from a private key.

    Args:
        private_key (bytes): key created by create_private_key()

    Returns:
        A public key that is safe to share (bytes).
    """
    return binascii.hexlify(
            nacl.public.PrivateKey(private_key).public_key._public_key
    ).decode()


def get_public_key_from_file(filename: str) -> str:
    """Get the public key from a private key.

    Args:
        private_key (bytes): key created by create_private_key()

    Returns:
        A public key that is safe to share (bytes).
    """

    with open(filename, 'rb') as fi:
        public_key = get_public_key(fi.read())
    return public_key


def encrypt(
        our_private_key_file: str, their_public_key: str, message: bytes
) -> str:
    """Encrypt a message using NaCl and an asymmetric key-pair.

    Args:
        our_private_key_file (str): name of our private key file
        their_public_key (bytes): pubic key of the system we are
            sending our message to
        message (bytes): message to encrypt

    Returns:
        An encrypted message (bytes).
    """

    with open(our_private_key_file, 'rb') as fi:
        our_private_key = fi.read()

    their_public_key = binascii.unhexlify(their_public_key).decode()

    box = nacl.public.Box(
            nacl.public.PrivateKey(our_private_key),
            nacl.public.PublicKey(their_public_key)
    )

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    enc = box.encrypt(message, nonce)

    return binascii.hexlify(enc).decode()


def decrypt(
        our_private_key_file: str, their_public_key: str, message: bytes
) -> str:
    """Decrypt a message using NaCl and an asymmetric key-pair.

    Args:
        our_private_key_file (str): name of our private key file
        their_public_key (str): pubic key of the system we received
            the message from
        message (bytes): message to decrypt

    Returns:
        A decrypted message (bytes).
    """

    with open(our_private_key_file, 'rb') as fi:
        our_private_key = fi.read()

    their_public_key = binascii.unhexlify(their_public_key).decode()

    msg = binascii.unhexlify(message)
    box = nacl.public.Box(
            nacl.public.PrivateKey(our_private_key),
            nacl.public.PublicKey(their_public_key)
    )
    dec = box.decrypt(msg)
    return dec
