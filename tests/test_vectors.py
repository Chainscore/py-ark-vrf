import json 
from pathlib import Path
from py_ark_vrf import verify_ring

def test_ring_verify():
    test_vectors = json.load(open(Path(__file__).parent / "bandersnatch_ell2.json"))

    for test_vector in test_vectors:
        pks= bytes.fromhex(test_vector["ring_pks"])
        ring = [
            bytes(pks[i*32:(i+1)*32]) for i in range(8)
        ]
        proof = (
            bytes.fromhex(test_vector["gamma"]) +
            bytes.fromhex(test_vector["proof_pk_com"]) +
            bytes.fromhex(test_vector["proof_r"]) +
            bytes.fromhex(test_vector["proof_ok"]) +
            bytes.fromhex(test_vector["proof_s"]) +
            bytes.fromhex(test_vector["proof_sb"]) +
            bytes.fromhex(test_vector["ring_proof"])
        )
        
        verify_out = verify_ring(
            bytes.fromhex(test_vector["alpha"]), 
            proof, 
            ring, 
            bytes.fromhex(test_vector["ad"])
        )
        
        assert verify_out
