#!/usr/bin/env python3
"""
Test file to demonstrate type checking functionality of py_ark_vrf.
This file can be used to verify that type stubs are working correctly.
"""

import py_ark_vrf
from typing import List, Tuple

def test_secret_generation():
    """Test secret generation with proper type hints."""
    seed: bytes = b'test_seed_12345678901234567890'
    secret_data: Tuple[bytes, bytes] = py_ark_vrf.secret_from_seed(seed)
    assert len(secret_data) == 2
    assert len(secret_data[0]) == 32  # public key
    assert len(secret_data[1]) == 32  # secret scalar

def test_public_key_derivation():
    """Test public key derivation with proper type hints."""
    seed: bytes = b'test_seed_12345678901234567890'
    secret_data = py_ark_vrf.secret_from_seed(seed)
    secret_scalar: bytes = secret_data[1]
    public_key: bytes = py_ark_vrf.public_from_le_secret(secret_scalar)
    assert len(public_key) == 32
    assert public_key == secret_data[0]  # Should match the original public key

def test_ring_operations():
    """Test ring operations with proper type hints."""
    # Generate a secret and public key
    seed: bytes = b'test_seed_12345678901234567890'
    secret_data = py_ark_vrf.secret_from_seed(seed)
    secret_scalar = secret_data[1]
    public_key = secret_data[0]
    
    # Create a ring of public keys
    ring: List[bytes] = [public_key, public_key]  # Same key twice for testing
    
    # Compute ring root
    ring_root: bytes = py_ark_vrf.get_ring_root(ring)
    assert len(ring_root) == 144

def test_vrf_operations():
    """Test VRF operations with proper type hints."""
    # Generate a secret and public key
    seed: bytes = b'test_seed_12345678901234567890'
    secret_data = py_ark_vrf.secret_from_seed(seed)
    secret_scalar = secret_data[1]
    
    # Generate IETF VRF proof
    input_data: bytes = b'test_input_data'
    aux_data: bytes = b'test_aux_data'
    
    proof: bytes = py_ark_vrf.prove_ietf(secret_scalar, input_data, aux_data)
    
    # Extract VRF output
    vrf_output: bytes = py_ark_vrf.vrf_output(proof)
    assert len(vrf_output) == 32

def test_srs_file_path():
    """Test SRS file path retrieval with proper type hints."""
    srs_path: str = py_ark_vrf.get_srs_file_path()
    assert isinstance(srs_path, str)
    assert srs_path.endswith('bandersnatch_ring.srs')