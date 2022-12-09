%lang starknet

from src.verify import verify_full_proof, Membership
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

@external
func test_verify_proof{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    alloc_locals;

    local state_root;
    local contract_class_hash;
    local contract_root;
    local contract_nonce;
    local contract_state_hash_version;
    local contract_key_len;
    let (local contract_key: felt*) = alloc();
    local contract_proof_len;
    let (local contract_proof: felt*) = alloc();
    local storage_proofs_len;
    let (local storage_proofs: felt*) = alloc();

    %{
        from tests.pymodule import get_storage_proof, get_contract_proof, get_json, parse_proof, flatten

        def translate_proof(p):
            res = []
            for item in p:
                to_add = item
                try:
                    to_add = int(to_add, 16)
                except:
                    pass
                res.append(to_add)
            return res

        def parse_key(key):
            print(key)
            print(int(key, 16))
            print(bin(int(key, 16)))
            print(list(bin(int(key, 16))))
            binary = [int(x) for x in list(bin(int(key, 16)))[2:]]
            key_bits = [0 for i in range(251 - len(binary))] + binary
            return (key_bits)

        j = get_json("/Users/pscott/Code/Snapshot/starknet_verifier/tests/data.json")

        contract_proof = get_contract_proof()

        ids.state_root = int("0x47f25798a804800b657d4e1508776e3c3c70f0d7587d125a558208f88570aa7", 16)
        ids.contract_class_hash = int(j['result']['contract_data']['class_hash'], 16)
        ids.contract_root = int(j['result']['contract_data']['root'], 16)
        ids.contract_nonce = int(j['result']['contract_data']['nonce'], 16)
        ids.contract_state_hash_version = int(j['result']['contract_data']['contract_state_hash_version'], 16)

        ids.contract_key_len = 251
        contract = "0x4d4e07157aeb54abeb64f5792145f2e8db1c83bda01a8f06e050be18cfb8153"
        binary = [int(x) for x in list(bin(int(contract, 16))[2:])]
        key_bits = [0 for i in range(251 - len(binary))] + binary
        segments.write_arg(ids.contract_key, key_bits)

        ids.contract_proof_len = len(contract_proof)
        contract_proof = translate_proof(contract_proof)
        segments.write_arg(ids.contract_proof, contract_proof)

        storage_proofs = j['result']['contract_data']['storage_proofs']
        flat_storage_proofs = []
        values = ["0x2"]
        keys = ["0x1"]
        for (i, proof) in enumerate(storage_proofs):
            parsed = parse_proof(proof)
            key = parse_key(keys[i])
            flat_storage_proofs += [ids.contract_root, values[i], len(key)]
            flat_storage_proofs += key
            flat = flatten(parsed)
            flat_storage_proofs += [len(flat)]
            flat_storage_proofs += flat
        print("len: ", len(flat_storage_proofs))
        print(flat_storage_proofs)
        flat_storage_proofs = translate_proof(flat_storage_proofs)

        ids.storage_proofs_len = len(flat_storage_proofs)
        segments.write_arg(ids.storage_proofs, flat_storage_proofs)

    %}
    let (res) = verify_full_proof(state_root, contract_class_hash, contract_root, contract_nonce, contract_state_hash_version, contract_key_len, contract_key, contract_proof_len, contract_proof, storage_proofs_len, storage_proofs);
    // assert res = Membership.Member;

    return ();
}
