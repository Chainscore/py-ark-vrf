use pyo3::prelude::*;
use std::fs::File;
use std::io::Read;
use std::vec;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use ark_vrf::suites::bandersnatch as suite;
type Suite  = suite::BandersnatchSha512Ell2;
type Secret = suite::Secret;
type Public = suite::Public;
type Input  = suite::Input;
type Output = suite::Output;
type ScalarField = suite::ScalarField;
type AffinePoint = suite::AffinePoint;

use ark_vrf::reexports::ark_ff::PrimeField;

use ark_vrf::ietf::{self, Prover as IetfProver, Verifier as IetfVerifier};
type IetfProof = ietf::Proof<Suite>;

use ark_vrf::pedersen::{self as ped, Prover as PedProver, Verifier as PedVerifier};
type PedersenProof = ped::Proof<Suite>;

use ark_vrf::ring::{self, Prover as RingProver, Verifier as RingVerifier};
type RingProof = ring::Proof<Suite>;
type RingProofParams = ring::RingProofParams<Suite>;


#[pyfunction]
fn secret_from_seed(seed: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let scrt = Secret::from_seed(seed);
    let mut pub_ = vec![];
    let mut scalar_ = vec![];

    scrt.public().serialize_compressed(&mut pub_);
    scrt.scalar.serialize_compressed(&mut scalar_);

    Ok((pub_, scalar_))
}


#[pyfunction]
fn public_from_le_secret(secret_scalar: &[u8]) -> PyResult<Vec<u8>> {
    let pub_ = Secret::from_scalar(ScalarField::from_le_bytes_mod_order(secret_scalar)).public();
    let mut pub_bytes = vec![];
    pub_.serialize_compressed(&mut pub_bytes);
    Ok(pub_bytes)
}


/* === IETF === */
#[pyfunction]
fn prove_ietf(
    secret_scalar_le: &[u8], 
    input_data: &[u8], 
    aux: &[u8]
) -> PyResult<Vec<u8>> {
    let secret = Secret::from_scalar(ScalarField::from_le_bytes_mod_order(secret_scalar_le));
    let input: Input = Input::new(input_data).unwrap();
    let output_pt = secret.output(input);

    let proof = IetfProver::prove(
        &secret,
        input.clone(),
        output_pt.clone(),
        aux,
    );

    let mut proof_bytes = vec![];
    proof.serialize_compressed(&mut proof_bytes);
    let mut output_pt_bytes = vec![];
    output_pt.serialize_compressed(&mut output_pt_bytes);

    Ok([output_pt_bytes, proof_bytes].concat())
}

#[pyfunction]
fn verify_ietf(
    pub_key: &[u8],
    proof: &[u8],
    input_data: &[u8],
    aux: &[u8]
) -> PyResult<bool> {
    let public = match AffinePoint::deserialize_compressed(pub_key) {
        Ok(p) => Public::from(p.into()),
        Err(_) => return Ok(false),
    };
    let output = match AffinePoint::deserialize_compressed(&proof[..32]) {
        Ok(p) => Output::from(p.into()),
        Err(_) => return Ok(false),
    };
    let input = match Input::new(input_data) {
        Some(i) => i,
        None => return Ok(false),
    };
    let proof_obj = match IetfProof::deserialize_compressed(&proof[32..]) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    match IetfVerifier::verify(&public, input, output, aux, &proof_obj) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}


/* === Pedersen === */
    // #[pyo3(signature = (input, aux = None))]
    // fn prove_pedersen(&self, input: &VRFInput, aux: Option<&[u8]>) -> PyResult<PedersenProof> {
    //     let output_pt = self.inner.output(input.inner.clone());
    //
    //     let (proof, _) = PedProver::prove(
    //         &self.inner,
    //         input.inner.clone(),
    //         output_pt.clone(),
    //         aux.unwrap_or(&[]),
    //     );
    //
    //     Ok(PedersenProof { inner: proof, output: VRFOutput { inner: output_pt } })
    // }


#[pyfunction]
fn prove_ring(
    secret_scalar: &[u8], 
    input_data: &[u8], 
    ring: Vec<Vec<u8>>, 
    aux: &[u8],
) -> PyResult<Vec<u8>> {
    let secret = Secret::from_scalar(ScalarField::from_le_bytes_mod_order(secret_scalar));
    let input = Input::new(input_data).unwrap();
    let pub_key: Vec<u8> = public_from_le_secret(secret_scalar).unwrap();
    let idx = ring 
        .iter()
        .position(|pk| *pk.as_slice() == *pub_key.as_slice()) 
        .expect("SecretKey's public key not in ring");
    
    let params = load_ring_params(ring.len());

    let pks: Vec<AffinePoint> = ring
        .iter()
        .map(|x| AffinePoint::deserialize_compressed(x.as_slice()).unwrap().into())
        .collect();
    let prover_key = params.prover_key(&pks);
    let prover = params.prover(prover_key, idx);
    let output_pt = secret.output(input.clone());

    let proof = RingProver::prove(
        &secret, 
        input.clone(), 
        output_pt.clone(), 
        aux, 
        &prover,
    );

    let mut proof_ = vec![];
    proof.serialize_compressed(&mut proof_);
    let mut output_ = vec![];
    output_pt.serialize_compressed(&mut output_);

    Ok([output_, proof_].concat())
}


#[pyfunction]
fn vrf_output(proof: &[u8]) -> PyResult<Vec<u8>> {
    let output_pt = Output::from(AffinePoint::deserialize_compressed(&proof[..32]).unwrap());
    return Ok(output_pt.hash()[..32].to_vec())
}

#[pyfunction]
fn verify_ring(
    input_data: &[u8],
    proof: &[u8], 
    ring: Vec<Vec<u8>>, 
    aux: &[u8]
) -> PyResult<bool> {
    let input = Input::new(input_data).unwrap();
    let output = match AffinePoint::deserialize_compressed(&proof[..32]) {
        Ok(p) => Output::from(p.into()),
        Err(_) => return Ok(false),
    };
    let pks: Vec<AffinePoint> = ring
        .iter()
        .map(|x| AffinePoint::deserialize_compressed(x.as_slice()).unwrap().into())
        .collect();

    let params = load_ring_params(pks.len());
    let verifier_key = params.verifier_key(&pks);
    let verifier = params.verifier(verifier_key);
    let proof_obj = match RingProof::deserialize_compressed(&proof[32..]) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    
    Ok(<Public as RingVerifier<Suite>>::verify(
        input.clone(), 
        output.clone(),
        aux, 
        &proof_obj,
        &verifier,
    ).is_ok())
}


#[pyfunction]
fn get_ring_root(public_keys_bytes: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    // Convert bytes to PublicKey objects
    let public_keys: Vec<AffinePoint> = public_keys_bytes
        .iter()
        .map(|x| AffinePoint::deserialize_compressed(x.as_slice())
            .unwrap_or_else(|_| RingProofParams::padding_point())
        )
        .collect();

    // Generate ring commitment
    let params = load_ring_params(public_keys.len());
    let verifier_key = params.verifier_key(&public_keys);
    let commitment = verifier_key.commitment();
    
    let mut ret_bytes = vec![];
    commitment.serialize_compressed(&mut ret_bytes);

    // Convert commitment to bytes
    Ok(ret_bytes)
}

use pyo3::Bound;
use pyo3::types::PyModule;

fn load_ring_params(ring_size: usize) -> ring::RingProofParams<Suite> {
    // Always load SRS from a fixed file for deterministic tests
    let srs_path = "bandersnatch_ring.srs";
    let mut file = File::open(srs_path).expect("SRS file not found");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("Failed to read SRS file");
    let pcs_params = ring::PcsParams::<Suite>::deserialize_uncompressed_unchecked(&mut &buf[..])
        .expect("Failed to deserialize SRS");
    ring::RingProofParams::from_pcs_params(ring_size, pcs_params).expect("Invalid SRS params")
}

#[pymodule]
fn py_ark_vrf(_py: Python<'_>, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(secret_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(public_from_le_secret, m)?)?;
    m.add_function(wrap_pyfunction!(get_ring_root, m)?)?;
    m.add_function(wrap_pyfunction!(prove_ietf, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ietf, m)?)?;
    m.add_function(wrap_pyfunction!(prove_ring, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ring, m)?)?;
    m.add_function(wrap_pyfunction!(vrf_output, m)?)?;
    Ok(())
}
