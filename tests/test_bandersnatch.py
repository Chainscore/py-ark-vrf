from py_ark_vrf import secret_from_seed, public_from_le_secret, prove_ietf, verify_ietf, prove_ring, verify_ring, vrf_output
import pytest
import time


@pytest.mark.parametrize("seed", [0, 100, 2**16, 2**32 - 1])
def test_from_seed(seed):
    pub, secret_scalar = secret_from_seed(seed.to_bytes(32))
    assert pub
    assert secret_scalar
    
    pub_from_scalar = public_from_le_secret(secret_scalar)
    assert pub_from_scalar == pub


@pytest.mark.parametrize("seed,input,ad", [
    (0, b"hello", b""),
    (128, b"what do we say to the gods of death", b"tomorrow")
])
def test_ietf(seed: int, input: bytes, ad: bytes):
    pub_key, scalar = secret_from_seed(seed.to_bytes(32))
    proof = prove_ietf(scalar, input, ad)
    assert proof 
    assert len(proof) == 96

    # verify the proof
    assert verify_ietf(pub_key, proof, input, ad)

    # false negatives
    assert not verify_ietf(pub_key, bytes(96), input, ad)
    
    # vrf output
    assert len(vrf_output(proof)) == 32

# FIX: Uses system randomness
# @pytest.mark.parametrize("seeds,index,input,ad", [
#     ([1,2,3,4,5,6], 1, b"hello", b"")
# ])
# def test_ring_proof(seeds: list[int], index: int, input: str, ad: str):
#     keys = [secret_from_seed(seed.to_bytes(32)) for seed in seeds]
#     ring = [k[0] for k in keys]
#     proof = prove_ring(keys[index][1], input, ring, ad)
#     print("proof", proof)


def test_ring_verify():
    test_vector = {
      "comment": "bandersnatch_sha-512_ell2_ring - vector-1",
      "sk": "3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18",
      "pk": "a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b",
      "alpha": "",
      "salt": "",
      "ad": "",
      "h": "c5eaf38334836d4b10e05d2c1021959a917e08eaf4eb46a8c4c8d1bec04e2c00",
      "gamma": "e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f",
      "beta": "fdeb377a4ffd7f95ebe48e5b43a88d069ce62188e49493500315ad55ee04d7442b93c4c91d5475370e9380496f4bc0b838c2483bce4e133c6f18b0adbb9e4722",
      "blinding": "01371ac62e04d1faaadbebaa686aaf122143e2cda23aacbaa4796d206779a501",
      "proof_pk_com": "3b21abd58807bb6d93797001adaacd7113ec320dcf32d1226494e18a57931fc4",
      "proof_r": "8123054bfdb6918e0aa25c3337e6509eea262282fd26853bf7cd6db234583f5e",
      "proof_ok": "ac57ce6a53a887fc59b6aa73d8ff0e718b49bd9407a627ae0e9b9e7c5d0d175b",
      "proof_s": "0d379b65fb1e6b2adcbf80618c08e31fd526f06c2defa159158f5de146104c0f",
      "proof_sb": "e2ca83136143e0cac3f7ee863edd3879ed753b995b1ff8d58305d3b1f323630b",
      "ring_pks": "7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9",
      "ring_pks_com": "afd34e92148ec643fbb578f0e14a1ca9369d3e96b821fcc811c745c320fe2264172545ca9b6b1d8a196734bc864e171484f45ba5b95d9be39f03214b59520af3137ea80e302730a5df8e4155003414f6dcf0523d15c6ef5089806e1e8e5782be92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf",
      "ring_proof": "98bc465cdf55ee0799bc25a80724d02bb2471cd7d065d9bd53a3a7e3416051f6e3686f7c6464c364b9f2b0f15750426a9107bd20fe94a01157764aab5f300d7e2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd93818c0c1c3bff5a793d026c604294d0bbd940ec5f1c652bb37dc47564d71dd1aa05aba41d1f0cb7f4442a88d9b533ba8e4788f711abdf7275be66d45d222dde988dedd0cb5b0d36b21ee64e5ef94e26017b674e387baf0f2d8bd04ac6faab057510b4797248e0cb57e03db0199cd77373ee56adb7555928c391de794a07a613f7daac3fc77ff7e7574eaeb0e1a09743c4dae2b420ba59cf40eb0445e41ffb2449021976970c858153505b20ac237bfca469d8b998fc928e9db39a94e2df1740ae0bad6f5d8656806ba24a2f9b89f7a4a9caef4e3ff01fec5982af873143346362a0eb9bb2f6375496ff9388639c7ffeb0bcee33769616e4878fc2315a3ac3518a9da3c4f072e0a0b583436a58524f036c3a1eeca023598682f1132485d3a57088b63acd86c6c72288568db71ff15b7677bfe7218acdebb144a2bf261eb4f65980f830e77f37c4f8d11eac9321f302a089698f3c0079c41979d278e8432405fc14d80aad028f79b0c4c626e4d4ac4e643692a9adfdc9ba2685a6c47eef0af5c8f5d776083895e3e01f1f944cd7547542b7e64b870b1423857f6362533f7cd2a01d231ffed60fe26169c28b28ace1a307fdc8d4b29f0b44659402d3d455d719d896f83b7ee927f0652ca883e4cfa85a2f4f7bc60dda1b068092923076893db5bd477fa2d26173314d7512760521d6ec9f"
    }
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
    
    start_time = time.time()
    verify_out = verify_ring(
        bytes.fromhex(test_vector["alpha"]), 
        proof, 
        ring, 
        bytes.fromhex(test_vector["ad"])
    )
    print("Verification time", time.time() - start_time)
    
    assert verify_out

    # false negatives
    assert not verify_ring(b"hello", proof, ring, b"")
