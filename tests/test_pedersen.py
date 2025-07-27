import json 
from pathlib import Path
from py_ark_vrf import prove_pedersen, verify_pedersen, vrf_output

def test_pedersen_verify():
    """Test Pedersen VRF verification against test vectors."""
    test_vectors = json.load(open(Path(__file__).parent / "bandersnatch_ell2_pedersen.json"))

    for test_vector in test_vectors:
        print(f"Testing: {test_vector['comment']}")
        
        # Construct the proof from test vector components
        proof = (
            bytes.fromhex(test_vector["gamma"]) +
            bytes.fromhex(test_vector["proof_pk_com"]) +
            bytes.fromhex(test_vector["proof_r"]) +
            bytes.fromhex(test_vector["proof_ok"]) +
            bytes.fromhex(test_vector["proof_s"]) +
            bytes.fromhex(test_vector["proof_sb"])
        )
        
        # Verify the proof
        verify_out = verify_pedersen(
            bytes.fromhex(test_vector["alpha"]), 
            proof, 
            bytes.fromhex(test_vector["ad"])
        )
        
        assert verify_out, f"Verification failed for {test_vector['comment']}"
        
        # Test VRF output
        output = vrf_output(proof)
        expected_beta = bytes.fromhex(test_vector["beta"])
        assert output == expected_beta[:32], f"VRF output mismatch for {test_vector['comment']}"

def test_pedersen_prove_verify():
    """Test full Pedersen VRF prove/verify cycle."""
    from py_ark_vrf import secret_from_seed
    
    # Use the first test vector's parameters for proving
    test_vectors = json.load(open(Path(__file__).parent / "bandersnatch_ell2_pedersen.json"))
    test_vector = test_vectors[0]
    
    # Generate keys from seed
    seed = bytes.fromhex(test_vector["sk"])
    keys = secret_from_seed(seed + b"0" * (32 - len(seed)))  # Pad to 32 bytes
    
    # Test proving
    input_data = bytes.fromhex(test_vector["alpha"]) if test_vector["alpha"] else b""
    aux_data = bytes.fromhex(test_vector["ad"]) if test_vector["ad"] else b""
    
    proof = prove_pedersen(keys[1], input_data, aux_data)
    
    # Test verification
    result = verify_pedersen(input_data, proof, aux_data)
    assert result, "Pedersen prove/verify cycle failed"
    
    # Test with wrong input (should fail)
    wrong_result = verify_pedersen(b"wrong_input", proof, aux_data)
    assert not wrong_result, "Verification should fail with wrong input"
    
    # Test VRF output
    output = vrf_output(proof)
    assert len(output) == 32, "VRF output should be 32 bytes"

def test_pedersen_deterministic():
    """Test that Pedersen VRF is deterministic."""
    from py_ark_vrf import secret_from_seed
    
    # Generate keys
    keys = secret_from_seed(b"test_seed_" + b"0" * 22)
    
    input_data = b"test_input"
    aux_data = b"test_aux"
    
    # Generate two proofs with same parameters
    proof1 = prove_pedersen(keys[1], input_data, aux_data)
    proof2 = prove_pedersen(keys[1], input_data, aux_data)
    
    # Should be identical (deterministic)
    assert proof1 == proof2, "Pedersen VRF should be deterministic"
    
    # Both should verify
    assert verify_pedersen(input_data, proof1, aux_data)
    assert verify_pedersen(input_data, proof2, aux_data)

if __name__ == "__main__":
    test_pedersen_verify()
    test_pedersen_prove_verify()
    test_pedersen_deterministic()
    print("All Pedersen tests passed!")
