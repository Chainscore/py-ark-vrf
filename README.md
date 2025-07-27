# `py-ark-vrf`

Python bindings for the [`ark-vrf`](https://github.com/w3f/ark-vrf) Rust crate, offering Verifiable Random Function (VRF) constructions. This library specifically uses the Bandersnatch curve (`suite::BandersnatchSha512Ell2`) and exposes three VRF schemes:

- **IETF VRF**: Standard VRF scheme following IETF specifications
- **Pedersen VRF**: Key-hiding VRF where the public key is not revealed during verification  
- **Ring VRF**: Anonymous VRF allowing proof of membership in a ring without revealing identity

This library requires a pre-generated SRS file `bandersnatch_ring.srs` for Ring VRF operations. The SRS file is automatically included in the package distribution and will be extracted when needed.

## Type Checking Support

This package includes type stubs (`.pyi` files) and supports static type checking with tools like mypy, PyCharm, and VS Code. The package is marked with `py.typed` to indicate type checking support.

## Installation

This package supports all major development platforms:
- **Linux** (x86_64, aarch64)
- **macOS** (Intel & Apple Silicon)  
- **Windows** (x64)

Install from PyPI:
```bash
pip install py-ark-vrf
```

Or build from source (requires Rust toolchain):
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build and install
pip install .
```

## Usage

### Key Generation

You can generate a secret/public key pair from a 32-byte seed. The public key can also be derived from the secret scalar.

```python
from py_ark_vrf import secret_from_seed, public_from_le_secret

# Generate keys from a seed
seed = 12345
public_key, secret_scalar = secret_from_seed(seed.to_bytes(32))

print(f"Public Key: {public_key.hex()}")
print(f"Secret Scalar: {secret_scalar.hex()}")

# Derive public key from the secret
derived_public_key = public_from_le_secret(secret_scalar)
assert derived_public_key == public_key
```

### IETF VRF

This scheme is defined in the IETF draft for VRFs. You can create and verify proofs.

```python
from py_ark_vrf import secret_from_seed, prove_ietf, verify_ietf, vrf_output

# 1. Key Generation
seed = 0
pub_key, scalar = secret_from_seed(seed.to_bytes(32))

# 2. Proving
input_data = b"hello"
ad = b"additional data" # associated data
proof = prove_ietf(scalar, input_data, ad)

assert len(proof) == 96

# 3. Verification
is_valid = verify_ietf(pub_key, proof, input_data, ad)
assert is_valid

# An invalid proof should fail verification
assert not verify_ietf(pub_key, bytes(96), input_data, ad)

# 4. Get VRF output hash
output = vrf_output(proof)
assert len(output) == 32
print(f"VRF Output: {output.hex()}")
```

### Pedersen VRF

Pedersen VRFs provide a key-hiding VRF construction where the public key is not revealed during verification. This can be useful in privacy-preserving applications where you want to verify randomness without exposing identity.

```python
from py_ark_vrf import secret_from_seed, prove_pedersen, verify_pedersen, vrf_output

# 1. Key Generation
seed = 0
pub_key, scalar = secret_from_seed(seed.to_bytes(32))

# 2. Proving (no public key needed)
input_data = b"hello"
ad = b"additional data"
proof = prove_pedersen(scalar, input_data, ad)

assert len(proof) == 192  # 32 bytes output + 160 bytes proof

# 3. Verification (no public key needed - key-hiding!)
is_valid = verify_pedersen(input_data, proof, ad)
assert is_valid

# An invalid proof should fail verification
assert not verify_pedersen(input_data, bytes(192), ad)

# 4. Get VRF output hash
output = vrf_output(proof)
assert len(output) == 32
print(f"VRF Output: {output.hex()}")
```

### Ring VRF

Ring VRFs allow proving that a secret key holder is part of a "ring" (a set of public keys) without revealing which one.

**Note:** Ring VRF operations require a Structured Reference String (SRS) file. The SRS file is automatically included in the package and will be extracted when needed. No manual setup is required.

```python
from py_ark_vrf import secret_from_seed, prove_ring, verify_ring

# 1. Setup a ring of public keys
seeds = [1, 2, 3, 4, 5, 6, 7, 8]
keys = [secret_from_seed(seed.to_bytes(32)) for seed in seeds]
ring = [k[0] for k in keys]

# 2. Select a prover from the ring
prover_index = 4
prover_secret_scalar = keys[prover_index][1]

# 3. Proving
input_data = b"message"
ad = b""
ring_proof = prove_ring(prover_secret_scalar, input_data, ring, ad)

# 4. Verification
# Anyone with the ring can verify the proof
is_valid = verify_ring(input_data, ring_proof, ring, ad)
assert is_valid

# Verification should fail with wrong input
assert not verify_ring(b"wrong message", ring_proof, ring, ad)
```

### API

#### `secret_from_seed(seed: bytes) -> (bytes, bytes)`
Generates a (public_key, secret_scalar) pair from a 32-byte seed.

#### `public_from_le_secret(secret_scalar: bytes) -> bytes`
Derives a public key from a secret scalar.

#### `prove_ietf(secret_scalar: bytes, input_data: bytes, aux_data: bytes) -> bytes`
Creates an IETF VRF proof. Returns a 96-byte proof.

#### `verify_ietf(public_key: bytes, proof: bytes, input_data: bytes, aux_data: bytes) -> bool`
Verifies an IETF VRF proof.

#### `prove_pedersen(secret_scalar: bytes, input_data: bytes, aux_data: bytes) -> bytes`
Creates a Pedersen VRF proof. Returns a 192-byte proof (32 bytes output + 160 bytes proof). Key-hiding - no public key is revealed.

#### `verify_pedersen(input_data: bytes, proof: bytes, aux_data: bytes) -> bool`
Verifies a Pedersen VRF proof. Key-hiding - no public key is required for verification.

#### `prove_ring(secret_scalar: bytes, input_data: bytes, ring: list[bytes], aux_data: bytes) -> bytes`
Creates a Ring VRF proof. The prover's public key must be in the `ring`.

#### `verify_ring(input_data: bytes, proof: bytes, ring: list[bytes], aux_data: bytes) -> bool`
Verifies a Ring VRF proof.

#### `vrf_output(proof: bytes) -> bytes`
Extracts the 32-byte VRF output hash from a proof (works for both IETF and Ring proofs).

#### `get_ring_root(public_keys: list[bytes]) -> bytes`
Returns a 144-bytes ring root
