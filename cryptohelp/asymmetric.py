# Copyright: 2018, CCX Technologies

import os
import binascii
import nacl.public


def key_to_str(key: bytes) -> str:
    """Convert a key to a string.

    Args:
        key (bytes): key to convert.

    Returns:
        Key as a string.
    """
    return binascii.hexlify(key).decode()


def key_from_str(key: str) -> bytes:
    """Convert a string key to a key.

    Args:
        key (str): key to convert.

    Returns:
        Key as a bytes.
    """
    return binascii.unhexlify(key)


def create_private_key() -> bytes:
    """Create a private key suitable for use with these asymmetric crypto tools.

    Returns:
        A tuple with two bytes typed values (private_key, public_key).
    """
    return nacl.public.PrivateKey.generate()._private_key


def create_private_key_file(filename: str):
    """Create a private key suitable for use with these asymmetric crypto tools,
        and store it in a file.
    """

    with open(filename, 'wb') as fo:
        fo.write(create_private_key())
    os.chmod(filename, 0o600)


def get_public_key(private_key: bytes) -> bytes:
    """Get the public key from a private key.

    Args:
        private_key (bytes): key created by create_private_key()

    Returns:
        A public key that is safe to share (bytes).
    """
    return nacl.public.PrivateKey(private_key).public_key._public_key


def get_public_key_from_file(filename: str) -> bytes:
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
        our_private_key: bytes, their_public_key: bytes, message: bytes
) -> str:
    """Encrypt a message using NaCl and an asymmetric key-pair.

    Args:
        our_private_key (bytes): key created by create_private_key()
        their_public_key (bytes): pubic key of the system we are
            sending our message to
        message (bytes): message to encrypt

    Returns:
        An encrypted message (bytes).
    """

    box = nacl.public.Box(
            nacl.public.PrivateKey(our_private_key),
            nacl.public.PublicKey(their_public_key)
    )
    enc = box.encrypt(message)
    return binascii.hexlify(enc).decode()


def decrypt(
        our_private_key: bytes, their_public_key: bytes, message: bytes
) -> str:
    """Decrypt a message using NaCl and an asymmetric key-pair.

    Args:
        our_private_key (bytes): key created by create_private_key()
        their_public_key (bytes): pubic key of the system we received
            the message from
        message (bytes): message to decrypt

    Returns:
        A decrypted message (bytes).
    """

    msg = binascii.unhexlify(message)
    box = nacl.public.Box(
            nacl.public.PrivateKey(our_private_key),
            nacl.public.PublicKey(their_public_key)
    )
    dec = box.decrypt(msg)
    return dec
