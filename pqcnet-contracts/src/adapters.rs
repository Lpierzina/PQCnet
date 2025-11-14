use crate::dsa::{MlDsa, MlDsaKeyPair};
use crate::error::{PqcError, PqcResult};
use crate::kem::{MlKem, MlKemEncapsulation, MlKemKeyPair};
use crate::types::{Bytes, SecurityLevel};
use alloc::vec::Vec;
use blake2::Blake2s256;
use digest::Digest;
use spin::Mutex;

const DOMAIN_MLKEM_SK: &[u8] = b"PQCNET_MLKEM_SK_V1";
const DOMAIN_MLKEM_PK: &[u8] = b"PQCNET_MLKEM_PK_V1";
const DOMAIN_MLKEM_CT: &[u8] = b"PQCNET_MLKEM_CT_V1";
const DOMAIN_MLKEM_SS: &[u8] = b"PQCNET_MLKEM_SS_V1";

const DOMAIN_MLDSA_SK: &[u8] = b"PQCNET_MLDSA_SK_V1";
const DOMAIN_MLDSA_PK: &[u8] = b"PQCNET_MLDSA_PK_V1";
const DOMAIN_MLDSA_SIG: &[u8] = b"PQCNET_MLDSA_SIG_V1";

/// Demo ML-KEM adapter backed by deterministic BLAKE2s derivations.
///
/// This stands in for the audited Autheo PQC engines inside the contract tests
/// and WASM demo builds. The adapter keeps the same trait surface so that
/// swapping in the real Kyber bindings requires no contract changes.
pub struct DemoMlKem {
    counter: Mutex<u64>,
}

impl DemoMlKem {
    /// Create a new deterministic ML-KEM adapter.
    pub const fn new() -> Self {
        Self {
            counter: Mutex::new(1),
        }
    }

    fn next_seed(&self) -> [u8; 32] {
        let mut guard = self.counter.lock();
        let current = *guard;
        *guard = current.wrapping_add(1);
        drop(guard);

        let mut seed = [0u8; 32];
        let derived = expand_bytes(DOMAIN_MLKEM_SK, &current.to_le_bytes(), 32);
        seed.copy_from_slice(&derived);
        seed
    }
}

impl MlKem for DemoMlKem {
    fn level(&self) -> SecurityLevel {
        SecurityLevel::MlKem128
    }

    fn keygen(&self) -> PqcResult<MlKemKeyPair> {
        let secret_seed = self.next_seed();
        let secret_key = secret_seed.to_vec();
        let public_key = expand_bytes(DOMAIN_MLKEM_PK, &secret_seed, 32);

        Ok(MlKemKeyPair {
            public_key,
            secret_key,
            level: self.level(),
        })
    }

    fn encapsulate(&self, public_key: &[u8]) -> PqcResult<MlKemEncapsulation> {
        if public_key.is_empty() {
            return Err(PqcError::InvalidInput("ml-kem pk missing"));
        }

        let ciphertext = expand_bytes(DOMAIN_MLKEM_CT, public_key, 48);
        let shared_secret = expand_bytes(DOMAIN_MLKEM_SS, &ciphertext, 32);

        Ok(MlKemEncapsulation {
            ciphertext,
            shared_secret,
        })
    }

    fn decapsulate(&self, _secret_key: &[u8], ciphertext: &[u8]) -> PqcResult<Bytes> {
        if ciphertext.is_empty() {
            return Err(PqcError::InvalidInput("ml-kem ciphertext missing"));
        }
        Ok(expand_bytes(DOMAIN_MLKEM_SS, ciphertext, 32))
    }
}

/// Demo ML-DSA adapter backed by deterministic BLAKE2s derivations.
pub struct DemoMlDsa {
    counter: Mutex<u64>,
}

impl DemoMlDsa {
    /// Create a new ML-DSA adapter.
    pub const fn new() -> Self {
        Self {
            counter: Mutex::new(7),
        }
    }

    fn next_seed(&self) -> [u8; 32] {
        let mut guard = self.counter.lock();
        let current = *guard;
        *guard = current.wrapping_add(1);
        drop(guard);

        let mut seed = [0u8; 32];
        let derived = expand_bytes(DOMAIN_MLDSA_SK, &current.to_le_bytes(), 32);
        seed.copy_from_slice(&derived);
        seed
    }
}

impl MlDsa for DemoMlDsa {
    fn level(&self) -> SecurityLevel {
        SecurityLevel::MlDsa128
    }

    fn keygen(&self) -> PqcResult<MlDsaKeyPair> {
        let secret_seed = self.next_seed();
        let secret_key = secret_seed.to_vec();
        let public_key = expand_bytes(DOMAIN_MLDSA_PK, &secret_seed, 32);
        Ok(MlDsaKeyPair {
            public_key,
            secret_key,
            level: self.level(),
        })
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> PqcResult<Bytes> {
        if secret_key.is_empty() {
            return Err(PqcError::InvalidInput("ml-dsa secret missing"));
        }

        let public_key = expand_bytes(DOMAIN_MLDSA_PK, secret_key, 32);
        let mut transcript =
            Vec::with_capacity(public_key.len() + message.len() + DOMAIN_MLDSA_SIG.len());
        transcript.extend_from_slice(DOMAIN_MLDSA_SIG);
        transcript.extend_from_slice(&public_key);
        transcript.extend_from_slice(message);

        let mut digest = Blake2s256::new();
        digest.update(&transcript);
        let sig = digest.finalize();
        Ok(sig.to_vec())
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> PqcResult<()> {
        if public_key.is_empty() {
            return Err(PqcError::InvalidInput("ml-dsa pk missing"));
        }
        if signature.len() != 32 {
            return Err(PqcError::InvalidInput("ml-dsa signature length invalid"));
        }

        let mut transcript =
            Vec::with_capacity(public_key.len() + message.len() + DOMAIN_MLDSA_SIG.len());
        transcript.extend_from_slice(DOMAIN_MLDSA_SIG);
        transcript.extend_from_slice(public_key);
        transcript.extend_from_slice(message);

        let mut digest = Blake2s256::new();
        digest.update(&transcript);
        let expected = digest.finalize();

        if expected.as_slice() == signature {
            Ok(())
        } else {
            Err(PqcError::VerifyFailed)
        }
    }
}

fn expand_bytes(domain: &[u8], input: &[u8], len: usize) -> Bytes {
    if len == 0 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 0;

    while out.len() < len {
        let mut digest = Blake2s256::new();
        digest.update(domain);
        digest.update(&(len as u32).to_le_bytes());
        digest.update(input);
        digest.update(&counter.to_le_bytes());

        let block = digest.finalize();
        let remaining = len - out.len();
        let chunk = &block[..remaining.min(block.len())];
        out.extend_from_slice(chunk);
        counter = counter.wrapping_add(1);
    }

    out
}
