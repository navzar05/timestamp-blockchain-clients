from web3 import Web3

# Connect to hardhat network
w3 = Web3(Web3.HTTPProvider("hardhat_node"))

print("Connected?", w3.is_connected())

# Print first hardhat account
accounts = w3.eth.accounts
print("First Hardhat account:", accounts[0])

# Print balance
balance = w3.eth.get_balance(accounts[0])
print("Balance (ETH):", w3.from_wei(balance, 'ether'))
print(w3.eth.gas_price)