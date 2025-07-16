#!/usr/bin/env python3
"""
Test file to demonstrate type checking functionality of py_ark_vrf.
This file can be used to verify that type stubs are working correctly.
"""

import py_ark_vrf
from typing import List, Tuple

def test_secret_generation() -> Tuple[bytes, bytes]:
    """Test secret generation with proper type hints."""
    seed: bytes = b'test_seed_12345678901234567890'
    secret_data: Tuple[bytes, bytes] = py_ark_vrf.secret_from_seed(seed)
    return secret_data

def test_public_key_derivation(secret_scalar: bytes) -> bytes:
    """Test public key derivation with proper type hints."""
    public_key: bytes = py_ark_vrf.public_from_le_secret(secret_scalar)
    return public_key

def test_ring_operations() -> bytes:
    """Test ring operations with proper type hints."""
    # Generate a secret and public key
    secret_data = test_secret_generation()
    secret_scalar = secret_data[1]
    public_key = test_public_key_derivation(secret_scalar)
    
    # Create a ring of public keys
    ring: List[bytes] = [public_key, public_key]  # Same key twice for testing
    
    # Compute ring root
    ring_root: bytes = py_ark_vrf.get_ring_root(ring)
    return ring_root

def test_vrf_operations() -> bytes:
    """Test VRF operations with proper type hints."""
    # Generate a secret and public key
    secret_data = test_secret_generation()
    secret_scalar = secret_data[1]
    
    # Generate IETF VRF proof
    input_data: bytes = b'test_input_data'
    aux_data: bytes = b'test_aux_data'
    
    proof: bytes = py_ark_vrf.prove_ietf(secret_scalar, input_data, aux_data)
    
    # Extract VRF output
    vrf_output: bytes = py_ark_vrf.vrf_output(proof)
    return vrf_output

def test_srs_file_path() -> str:
    """Test SRS file path retrieval with proper type hints."""
    srs_path: str = py_ark_vrf.get_srs_file_path()
    return srs_path