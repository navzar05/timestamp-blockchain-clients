import json
from web3 import Web3


w3 = Web3(Web3.HTTPProvider("https://eth-sepolia.g.alchemy.com/v2/<API_KEY>"))

assert w3.is_connected(), "Connection to Sepolia testnet failed!"

account_address = "account_address_in_hex_format" 
private_key = "account_private_key"      

# Load ABI + bytecode
with open("artifacts/contracts/DocumentRegistry.sol/DocumentRegistry.json") as f:
    artifact = json.load(f)

abi = artifact["abi"]
bytecode = artifact["bytecode"]

DocumentRegistry = w3.eth.contract(abi=abi, bytecode=bytecode)

nonce = w3.eth.get_transaction_count(account_address)
tx = DocumentRegistry.constructor().build_transaction({
    "from": account_address,
    "nonce": nonce,
    "gas": 3_000_000,
    "gasPrice": w3.eth.gas_price,
})

signed_tx = w3.eth.account.sign_transaction(tx, private_key)

tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
print(f"⏳ Deploy in progress... Tx hash: {tx_hash.hex()}")

tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Contract DocumentRegistry deployed to: {tx_receipt.contractAddress}")
