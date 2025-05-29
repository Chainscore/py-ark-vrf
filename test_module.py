import py_ark_vrf as vrf
import os
import random

def test_basic_vrf():
    # Create a secret key
    sk = vrf.SecretKey(bytes(32))
    pk = sk.public()
    
    # Create a VRF input
    input_data = b"test input"
    vrf_input = vrf.VRFInput(input_data)
    
    # Generate IETF proof
    ietf_proof = sk.prove_ietf(vrf_input)
    assert pk.verify_ietf(vrf_input, ietf_proof.output, ietf_proof)
    
    # Generate Pedersen proof
    pedersen_proof = sk.prove_pedersen(vrf_input)
    assert pk.verify_pedersen(vrf_input, pedersen_proof.output, pedersen_proof)
    
    # Verify output hash
    output_hash = ietf_proof.output.hash()
    assert len(output_hash) == 64  # SHA-512 hash length

def test_deterministic_vrf():
    # Create a secret key with a fixed seed
    seed = b"test seed 123"
    sk = vrf.SecretKey(seed)
    pk = sk.public()
    
    # Create a VRF input
    input_data = b"test input"
    vrf_input = vrf.VRFInput(input_data)
    
    # Generate two proofs with the same input and seed
    proof1 = sk.prove_ietf(vrf_input)
    proof2 = sk.prove_ietf(vrf_input)
    
    # The proofs should be identical
    assert proof1.to_bytes() == proof2.to_bytes()

def test_ring_proof():
    # Create a ring of public keys
    ring_size = 4
    ring = []
    secret_keys = []
    for i in range(ring_size):
        sk = vrf.SecretKey(f"key_{i}".encode())
        secret_keys.append(sk)
        ring.append(sk.public())
    
    # Create a VRF input
    input_data = b"test ring input"
    vrf_input = vrf.VRFInput(input_data)
    
    # Generate a ring proof using the first key
    prover_sk = secret_keys[0]
    # ring_proof = prover_sk.prove_ring(vrf_input, ring)
    
    # # Verify the ring proof
    # assert ring[0].verify_ring(vrf_input, ring_proof.output, ring_proof, ring)
    
    # Test ring commitment
    commitment = ring[0].get_ring_commitment(ring)
    print(commitment.to_bytes().hex(), ring)
    # assert ring[0].verify_ring_with_commitment(vrf_input, ring_proof.output, ring_proof, commitment)
    
    # # Test serialization
    # proof_bytes = ring_proof.to_bytes()
    # commitment_bytes = commitment.to_bytes()
    
    # # Test deserialization
    # new_proof = vrf.RingProof.from_bytes(proof_bytes, ring_proof.output)
    # new_commitment = vrf.RingCommitment.from_bytes(commitment_bytes)
    
    # # Verify with deserialized objects
    # assert ring[0].verify_ring(vrf_input, new_proof.output, new_proof, ring)
    # assert ring[0].verify_ring_with_commitment(vrf_input, new_proof.output, new_proof, new_commitment)

def test_ring_vectors():
    print("Testing ring VRF test vectors (placeholder)...")
    # TODO: Load and check vectors from ark-vrf/data/vectors/
    # This will require parsing the vector format and using RingProof.from_bytes
    pass

if __name__ == "__main__":
    # Ensure SRS file exists
    if not os.path.exists("bandersnatch_ring.srs"):
        print("Error: bandersnatch_ring.srs file not found")
        exit(1)
        
    # Run tests
    test_basic_vrf()
    test_deterministic_vrf()
    test_ring_proof()
    # test_ring_vectors()
    print("All tests passed!")
