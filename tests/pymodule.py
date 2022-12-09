import json
from starkware.crypto.signature.signature import pedersen_hash

def get_json(path):
    with open(path, 'r') as f:
        data = json.load(f)
        return data

def parse_proof(proof_array):
    print(proof_array)
    res = []
    for proof in proof_array:
        if "Binary" in proof:
            # Binary
            type = 1
            binary = proof['Binary']
            left_hash = binary['left']
            right_hash = binary['right']
            res.append([type, left_hash, right_hash])
        elif "Edge" in proof:
            edge = proof['Edge']
            type = 2
            child_hash = edge['child']
            path = edge['path']
            path_len = path['len']
            value = path['value']
            bits = list(bin(int(value, 16))[2:])
            if len(bits) < int(path_len):
                prepend = ['0' for _ in range(int(path_len) - len(bits))]
                bits = prepend + bits
            elif len(bits) > int(path_len):
                print("ERROR")
                print(proof)
                return
            ans = [type, child_hash, value, path_len]
            ans += bits
            res.append(ans)
        else:
            # Error
            print("parse proof ERROR")
            print(proof)
            return 
    return res

def flatten(l):
    return [item for sublist in l for item in sublist]

def get_contract_proof():
    data = get_json("tests/data.json")
    contract_proof = data['result']['contract_proof']
    parsed = parse_proof(contract_proof)
    print(parsed)
    return flatten(parsed)

def get_storage_proof():
    data = get_json("/Users/pscott/Code/Snapshot/starknet_verifier/tests/data.json")
    parsed = parse_proof(data['result']['contract_data']['storage_proofs'][0])
    return flatten(parsed)

def get_root(proof):
    type = proof[0]
    if type == 0:
        # Binary
        return pedersen_hash([int(proof[1], 16), int(proof[2], 16)])
    else:
        return 0
