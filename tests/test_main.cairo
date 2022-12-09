%lang starknet

from src.verify import verify_proof, Membership
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc

// @external
// func test_verify_proof{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
//     alloc_locals;

//     local root;
//     local value;
//     local key_len;
//     let (local key: felt*) = alloc();
//     local proof_len;
//     let (local proof: felt*) = alloc();

//     %{
//         from tests.pymodule import get_storage_proof, get_contract_proof

//         def translate_proof(p):
//             res = []
//             for item in p:
//                 to_add = item
//                 try:
//                     to_add = int(to_add, 16)
//                 except:
//                     pass
//                 res.append(to_add)
//             return res


//         proof = get_contract_proof()

//         ids.root = int("0x47f25798a804800b657d4e1508776e3c3c70f0d7587d125a558208f88570aa7", 16)

//         ids.key_len = 251
//         contract = "0x4d4e07157aeb54abeb64f5792145f2e8db1c83bda01a8f06e050be18cfb8153"
//         binary = [int(x) for x in list(bin(int(contract, 16))[2:])]
//         key_bits = [0 for i in range(251 - len(binary))] + binary
//         segments.write_arg(ids.key, key_bits)

//         ids.proof_len = len(proof)
//         proof = translate_proof(proof)
//         print("proof", proof)
//         segments.write_arg(ids.proof, proof)
//     %}
//     let (res) = verify_proof(root, value, key_len, key, proof_len, proof);
//     %{
//         a = ids.res
//         print("res", hex(a))
//     %}
//     assert res = Membership.Member;

//     return ();
// }
