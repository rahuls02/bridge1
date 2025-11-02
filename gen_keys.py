from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
import eth_account
import os

KEYFILE_DEFAULT = "secret_key.txt"

def _load_or_create_privkey(filename: str) -> str:
    """
    Returns a hex private key string (with 0x prefix).
    If the file doesn't exist or is empty/blank, create a new account and save its key.
    """
    with open(filename, "r") as f:
        lines = [ln.strip() for ln in f.readlines()]

    lines = [ln for ln in lines if ln]
    if not lines:
        acct = Account.create()
        with open(filename, "w") as f:
            f.write(acct.key.hex())
        return acct.key.hex()

    priv_hex = lines[0]
    if not priv_hex.startswith("0x") and not priv_hex.startswith("0X"):
        priv_hex = "0x" + priv_hex
    return priv_hex

def sign_message(challenge, filename="secret_key.txt"):
    """
    filename - filename of the file that contains your account secret key
    To pass the tests, your signature must verify, and the account you use
    must have testnet funds on both the bsc and avalanche test networks.
    """
    priv_hex = _load_or_create_privkey(filename)

    message = encode_defunct(challenge)

    acct = Account.from_key(priv_hex)
    signed_message = acct.sign_message(message)
    eth_addr = acct.address

    assert eth_account.Account.recover_message(
        message, signature=signed_message.signature.hex()
    ) == eth_addr, "Failed to sign message properly"

    return signed_message, eth_addr

if __name__ == "__main__":
    for _ in range(4):
        challenge = os.urandom(64)
        sig, addr = sign_message(challenge=challenge)
        print(addr)