import requests
from  starkware.crypto.signature.signature import pedersen_hash

url = "http://127.0.0.1:9545/rpc/v0.2"
headers = {"Content-Type": "application/json"}

blockid = 4773

data = {
 "jsonrpc":"2.0",
 "method":"starknet_getBlockWithTxs",
    "params": [{"block_number": blockid}],
 "id":1
}

response = requests.post(url, headers=headers, json=data)
ans = response.json()
print(ans)
root = ans["result"]["new_root"]
print("Global State Root: ", root)
print("\n\n")

data = {
 "jsonrpc":"2.0",
 "method":"pathfinder_getProof",
    "params": ["0x4d4e07157aeb54abeb64f5792145f2e8db1c83bda01a8f06e050be18cfb8153", ["1"], {"block_number": blockid}],
 "id":2
}

response = requests.post(url, headers=headers, json=data)
ans = response.json()
data = ans["result"]["contract_data"]
print(ans)
left = ans["result"]["contract_proof"][0]['Binary']['left']
right = ans["result"]["contract_proof"][0]['Binary']['right']
print(left, right)
print("hash ", hex(pedersen_hash(int(left, 16), int(right, 16))))
print("\n\n")

class_hash = int(data["class_hash"], 16)
nonce = int(data["nonce"], 16)
contract_version = int(data["contract_state_hash_version"], 16)
contract_root = int(data["root"], 16)

a = pedersen_hash(class_hash, contract_root)
b = pedersen_hash(a, nonce)
value = pedersen_hash(b, contract_version)
# h2 = pedersen_hash(class_hash, contract_root, nonce, contract_version)
print("contract value", hex(value))