%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.hash_state import hash_init, hash_update, hash_finalize, hash2
from starkware.cairo.common.alloc import alloc

// Result of verifying a proof:
// Error if the proof has a hash mismatch (it's wrong)
// NonMember if the proof proves that the requested key is NOT present in the tree
// Member if the `value` located at `key` is indeed part of the tree root at `root`
namespace Membership {
    const Error = 0;
    const Member = 1;
    const NonMember = 2;
}

// Hashes a binary node
func hash_binary{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(left_hash: felt, right_hash: felt) -> (hash: felt) {
    let (hash) = hash2{hash_ptr=pedersen_ptr}(left_hash, right_hash);
    return (hash=hash);
}

// Hashes an edge node
func hash_edge{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(path_value: felt, path_len: felt, child_hash: felt) -> (hash: felt) {
    let (hash) = hash2{hash_ptr=pedersen_ptr}(child_hash, path_value);
    return (hash=hash + path_len); // will wrap on overflow, expected behaviour
}

// Computes the contract state hash
func compute_contract_state_hash{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(class_hash: felt, root: felt, nonce: felt, version: felt) -> (contract_state_hash: felt) {
    let (h1) = hash2{hash_ptr=pedersen_ptr}(class_hash, root);
    let (h2) = hash2{hash_ptr=pedersen_ptr}(h1, nonce);
    let (h3) = hash2{hash_ptr=pedersen_ptr}(h2, version);
    return (contract_state_hash=h3);
}

// 
func matching_paths(path_bits_len: felt, path_bits: felt*, key_len: felt, key: felt*) -> (matches: felt) {
    if (path_bits_len == 0) {
        return (matches=TRUE);
    }

    if (key_len == 0) {
        return (matches=FALSE);
    }

    if (path_bits[0] == key[0]) {
        return matching_paths(path_bits_len - 1, &path_bits[1], key_len - 1, &key[1]);
    } else {
        return (matches=FALSE);
    }
}

// Returns 1 (Member), 2 (NonMember) or 0 (Error)
// 1. init expected_hash <- root hash
// 2. loop over nodes: current <- nodes[i]
// 1. verify the current node's hash matches expected_hash (if not then we have a bad proof)
// 2. move towards the target - if current is:
//    1. binary node then choose the child that moves towards the target, else if
//    2. edge node then check the path against the target bits
//       1. If it matches then proceed with the child, else
//       2. if it does not match then we now have a proof that the target does not exist
// 3. nibble off target bits according to which child you got in (2). If all bits are gone then you have reached the target and the child hash is the value you wanted and the proof is complete.
// 4. set expected_hash <- to the child hash
func verify_proof_recurse{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(expected_hash: felt, value: felt, key_len: felt, key: felt*, proof_len: felt, proof: felt*) -> (membership: felt) {
    alloc_locals;

    if (proof_len == 0) {
        if (expected_hash == value) {
            return (membership=Membership.Member);
        } else {
            return (membership=Membership.Error);
        }
    }

    let type = proof[0];

    if (type == 1) {
        // Binary
        local left = proof[1];
        local right = proof[2];
        let (hash) = hash_binary(proof[1], proof[2]);
        if (hash != expected_hash) {
            return (membership=Membership.Error);
        }

        let direction = key[0];
        if (direction == 1) {
            tempvar next_expected_hash = proof[2];
        } else {
            if (direction == 0) {
                tempvar next_expected_hash = proof[1];
            } else {
                return (membership=Membership.Error);
            }
        }
        return verify_proof_recurse(next_expected_hash, value, key_len - 1, &key[1], proof_len - 3, &proof[3]);
    } else {
        if (type == 2) {
            // Edge
            let type = proof[0];
            let edge_child_hash = proof[1];
            let edge_path_value = proof[2];
            let edge_path_len = proof[3];
            let edge_path_bits = &proof[4];
            let (hash) = hash_edge(edge_path_value, edge_path_len, edge_child_hash);

            if (hash != expected_hash) {
                return (membership=Membership.Error);
            }

            // check path matches
            let (match) = matching_paths(edge_path_len, edge_path_bits, key_len, key);
            if (match == FALSE) {
                return (membership=Membership.NonMember);
            }

            let total_len = 4 + edge_path_len;
            return verify_proof_recurse(edge_child_hash, value, key_len - edge_path_len, &key[edge_path_len], proof_len - total_len, &proof[total_len]);
        } else {
            return (membership=Membership.Error);
        }
    }
}

func verify_storage_proofs{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(storage_proofs_len: felt, storage_proofs: felt*) -> (membership: felt) {

    if (storage_proofs_len == 0) {
        return (membership=Membership.Member);
    } else {
        let root = storage_proofs[0];
        let value = storage_proofs[1];
        let key_len = storage_proofs[2];
        let key = &storage_proofs[3];
        let proof_len = storage_proofs[3 + key_len];
        let proof = &storage_proofs[4 + key_len];
        let total_len = 4 + key_len + proof_len;
        let (membership) = verify_proof(root, value, key_len, key, proof_len, proof);
        if (membership != Membership.Member) {
            return (membership=membership);
        } else {
            return verify_storage_proofs(storage_proofs_len - total_len, &storage_proofs[total_len]);
        }
    }
}

// Verifies a single proof, i.e verifies that `value` is found when you go down the tree rooted at `root`, following `key` and using 
// `proof` to verify the hashes.
@external
func verify_proof{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(root: felt, value: felt, key_len: felt, key: felt*, proof_len: felt, proof: felt*) -> (membership: felt) {
    if (key_len != 251) {
        return (membership=Membership.Error);
    }

    return verify_proof_recurse(root, value, key_len, key, proof_len, proof);
}

// Verifies a full proof, i.e first verifies the contract proof and then verifies each storage proofs.
// Returns `Member` if the contract *and* every storage proof is a `Member` : else returns the first `NonMemebership`
// or `Error` found.
@external
func verify_full_proof{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(state_root: felt, contract_class_hash: felt, contract_root: felt, contract_nonce: felt, contract_state_hash_version: felt, contract_key_len: felt, contract_key: felt*, contract_proof_len: felt, contract_proof: felt*,
   storage_proofs_len: felt, storage_proofs: felt* 
) -> (membership: felt) {
    let (contract_state_hash) = compute_contract_state_hash(contract_class_hash, contract_root, contract_nonce, contract_state_hash_version);

    let (contract_verified) = verify_proof(state_root, contract_state_hash, contract_key_len, contract_key, contract_proof_len, contract_proof);
    if (contract_verified != Membership.Member) {
        return (membership=contract_verified);
    }

    return verify_storage_proofs(storage_proofs_len, storage_proofs);
}
