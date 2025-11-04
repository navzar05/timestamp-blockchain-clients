from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://eth-sepolia.g.alchemy.com/v2/<API_KEY>"))
address = "account_address"
balance = w3.eth.get_balance(address)
print("ETH test:", w3.from_wei(balance, 'ether'))