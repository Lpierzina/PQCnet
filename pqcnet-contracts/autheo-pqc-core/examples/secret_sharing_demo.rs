use autheo_pqc_core::adapters::DemoMlKem;
use autheo_pqc_core::error::PqcResult;
use autheo_pqc_core::kem::{MlKemEngine, MlKemKeyPair};
use autheo_pqc_core::key_manager::{KemKeyState, KemRotation, KeyManager, ThresholdPolicy};
use autheo_pqc_core::secret_sharing::{combine_secret, split_secret, SecretSharePackage};
use autheo_pqc_core::types::TimestampMs;
use std::boxed::Box;

fn main() -> PqcResult<()> {
    println!("=== Threshold secret sharing demo ===");

    run_bootstrap_demo(
        "2-of-3 bootstrap",
        ThresholdPolicy { t: 2, n: 3 },
        1_706_000_000_000,
        120_000,
    )?;

    run_rotation_demo(
        "3-of-5 rotation & reshare",
        ThresholdPolicy { t: 3, n: 5 },
        1_706_000_120_000,
        45_000,
    )?;

    Ok(())
}

fn run_bootstrap_demo(
    label: &str,
    policy: ThresholdPolicy,
    now_ms: TimestampMs,
    rotation_interval_ms: u64,
) -> PqcResult<()> {
    println!("\n[{label}]");
    let mut manager = build_manager(policy, rotation_interval_ms);
    let (state, pair) = manager.keygen_with_material(now_ms)?;
    let package = share_package(&state, &pair, policy)?;
    log_package("initial distribution", &package);
    verify_quorum("initial quorum", &pair.secret_key, &package)?;
    Ok(())
}

fn run_rotation_demo(
    label: &str,
    policy: ThresholdPolicy,
    start_ms: TimestampMs,
    rotation_interval_ms: u64,
) -> PqcResult<()> {
    println!("\n[{label}]");
    let mut manager = build_manager(policy, rotation_interval_ms);
    let (state, pair) = manager.keygen_with_material(start_ms)?;
    let package = share_package(&state, &pair, policy)?;
    log_package("bootstrap distribution", &package);
    verify_quorum("bootstrap quorum", &pair.secret_key, &package)?;

    let rotate_at = start_ms + rotation_interval_ms + 1;
    let rotation = manager
        .rotate_with_material(rotate_at)?
        .expect("rotation should trigger after interval");
    log_rotation(&rotation);

    let reshared = split_secret(
        &rotation.new_material.secret_key,
        &rotation.new.id,
        rotation.new.version,
        rotation.new.created_at,
        policy,
    )?;
    log_package("reshared distribution", &reshared);
    verify_quorum(
        "post-rotation quorum",
        &rotation.new_material.secret_key,
        &reshared,
    )?;
    Ok(())
}

fn build_manager(policy: ThresholdPolicy, rotation_interval_ms: u64) -> KeyManager {
    let engine = MlKemEngine::new(Box::new(DemoMlKem::new()));
    KeyManager::new(engine, policy, rotation_interval_ms)
}

fn share_package(
    state: &KemKeyState,
    pair: &MlKemKeyPair,
    policy: ThresholdPolicy,
) -> PqcResult<SecretSharePackage> {
    split_secret(
        &pair.secret_key,
        &state.id,
        state.version,
        state.created_at,
        policy,
    )
}

fn verify_quorum(label: &str, expected: &[u8], package: &SecretSharePackage) -> PqcResult<()> {
    let threshold = package.threshold.t as usize;
    let quorum = &package.shares[..threshold];
    let recovered = combine_secret(quorum)?;
    assert_eq!(recovered.secret.as_slice(), expected);
    println!(
        "✔ {label}: reconstructed {} bytes using {} share(s)",
        recovered.secret.len(),
        threshold
    );
    Ok(())
}

fn log_package(label: &str, package: &SecretSharePackage) {
    println!(
        "{label}: key={} v{} created={} threshold {}-of-{}",
        short_id(&package.key_id.0),
        package.key_version,
        package.created_at,
        package.threshold.t,
        package.threshold.n
    );
    for share in &package.shares {
        println!(
            "  • share {:>2}: id={} v{} created={} len={} bytes",
            share.metadata.share_index,
            short_id(&share.metadata.key_id.0),
            share.metadata.key_version,
            share.metadata.created_at,
            share.value.len()
        );
    }
}

fn log_rotation(rotation: &KemRotation) {
    println!(
        "→ rotation: id {} (v{}) → id {} (v{})",
        short_id(&rotation.old.id.0),
        rotation.old.version,
        short_id(&rotation.new.id.0),
        rotation.new.version
    );
}

fn short_id(id: &[u8; 32]) -> String {
    let hex = hex_bytes(id);
    format!("{}…{}", &hex[..8], &hex[hex.len() - 4..])
}

fn hex_bytes(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
