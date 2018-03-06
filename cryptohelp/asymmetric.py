# Copyright: 2018, CCX Technologies

import binascii
import nacl.public


def create_private_key() -> bytes:
    """Create a private key suitable for use with these asymmetric crypto tools.

    Returns:
        A tuple with two bytes typed values (private_key, public_key).
    """
    return nacl.public.PrivateKey.generate()._private_key


def get_public_key(private_key: bytes) -> bytes:
    """Get the public key from a private key.

    Args:
        private_key (bytes): key created by create_private_key()

    Returns:
        A public key that is safe to share (bytes).
    """
    return nacl.public.PrivateKey(private_key).public_key._public_key


def encrypt_string(
        our_private_key: bytes, their_public_key: bytes, message: str
) -> str:
    """Encrypt a string using NaCl and an asymmetric key-pair.

    Args:
        our_private_key (bytes): key created by create_private_key()
        their_public_key (bytes): pubic key of the system we are
            sending our message to
        message (str): message to encrypt

    Returns:
        An encrypted message (str).
    """

    box = nacl.public.Box(
            nacl.public.PrivateKey(our_private_key),
            nacl.public.PublicKey(their_public_key)
    )
    enc = box.encrypt(message.encode('utf-8'))
    return binascii.hexlify(enc).decode('utf-8')


def decrypt_string(
        our_private_key: bytes, their_public_key: bytes, message: str
) -> str:
    """Decrypt a string using NaCl and an asymmetric key-pair.

    Args:
        our_private_key (bytes): key created by create_private_key()
        their_public_key (bytes): pubic key of the system we received
            the message from
        message (str): message to decrypt

    Returns:
        A decrypted message (str).
    """

    msg = binascii.unhexlify(message.encode('utf-8'))
    box = nacl.public.Box(
            nacl.public.PrivateKey(our_private_key),
            nacl.public.PublicKey(their_public_key)
    )
    dec = box.decrypt(msg)
    return dec.decode('utf-8')
