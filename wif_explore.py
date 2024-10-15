import hashlib
from bit import Key
import base58

def wif_to_number(wif_key):
    """
    Converts a WIF (Wallet Import Format) key into a numerical private key.
    
    Args:
        wif_key (str): The WIF-encoded private key.
    
    Returns:
        int: The private key as an integer.
    """
    decoded = base58.b58decode(wif_key)
    private_key_bytes = decoded[1:-4]
    private_key_number = int.from_bytes(private_key_bytes, byteorder='big')
    return private_key_number


def number_to_wif(private_key_number):
    """
    Converts a numerical private key into WIF format (uncompressed).
    
    Args:
        private_key_number (int): The private key as an integer.
    
    Returns:
        str: The WIF-encoded private key.
    """
    private_key_bytes = private_key_number.to_bytes(32, byteorder='big')
    prefix = b'\x80'  # Uncompressed WIF keys use 0x80 prefix for mainnet.
    prefixed_key = prefix + private_key_bytes

    checksum_full = hashlib.sha256(hashlib.sha256(prefixed_key).digest()).digest()
    checksum = checksum_full[:4]

    wif = base58.b58encode(prefixed_key + checksum)
    return wif.decode()


def wif_to_bytes(wif_key):
    """
    Converts a WIF key into its raw byte form.
    
    Args:
        wif_key (str): The WIF-encoded private key.
    
    Returns:
        bytes: The raw private key bytes.
    """
    decoded = base58.b58decode(wif_key, autofix=True)
    private_key_bytes = decoded[1:-4]
    return private_key_bytes


if __name__ == "__main__":
    wif = "WIF_HERE"
    
    # Print the Bitcoin address derived from the WIF
    print(f"Bitcoin Address: {Key.from_bytes(wif_to_bytes(wif)).address}")
    
    # Print the numerical representation of the private key
    print(f"Private Key (Number): {wif_to_number(wif)}")
