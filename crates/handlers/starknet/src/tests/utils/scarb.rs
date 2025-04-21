use crate::utils::{declare_contract, deploy_contract, WaitForReceipt};
use crate::StarknetWallet;
use once_cell::sync::Lazy;
use rstest::*;
use serde_json;
use starknet::accounts::ConnectedAccount;
use starknet::core::types::contract::CompiledClass;
use starknet::core::types::contract::SierraClass;
use starknet::core::types::BlockId;
use starknet::core::types::BlockTag;
use starknet::core::types::DeclareTransactionResult;
use starknet::core::types::Felt;
use starknet::providers::Provider;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;

static BUILT_PATHS: Lazy<Mutex<HashSet<PathBuf>>> = Lazy::new(|| Mutex::new(HashSet::new()));
pub type ArtifactsMap = HashMap<String, Artifacts>;

/// Runs scarb build in the specified directory and returns the parsed artifacts
#[fixture]
pub async fn scarb_build(#[default(".")] path: impl AsRef<Path>) -> ArtifactsMap {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR environment variable not set");

    let full_path = PathBuf::from(manifest_dir).join(path);
    let canonical_path = full_path.canonicalize().unwrap_or(full_path.clone());

    // Check if this path has already been built
    let mut built_paths = BUILT_PATHS.lock().expect("Failed to lock BUILT_PATHS");
    if built_paths.contains(&canonical_path) {
        return parse_starknet_artifacts(&canonical_path).unwrap();
    }

    let output = Command::new("scarb")
        .arg("build")
        .current_dir(&full_path)
        .output()
        .expect("Failed to execute scarb build");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!(
            "Scarb build failed!\nStdout: {}\nStderr: {}",
            stdout, stderr
        );
        panic!("Scarb build failed");
    }

    // Add the path to the set of built paths
    built_paths.insert(canonical_path.clone());

    // Parse and return the artifacts
    parse_starknet_artifacts(&canonical_path).unwrap()
}

/// Runs scarb build in multiple directories and merges their artifacts
/// Couldn't figure out fixtures + vector arguments, so made a function for now
pub async fn scarb_builds(paths: Vec<impl AsRef<Path>>) -> ArtifactsMap {
    let mut merged_artifacts = ArtifactsMap::new();

    for path in paths {
        let artifacts = scarb_build(path).await;
        merged_artifacts.extend(artifacts);
    }

    merged_artifacts
}

#[derive(Debug, Clone)]
pub struct Artifacts {
    pub class_hash: Felt,
    pub compiled_class_hash: Felt,
    pub contract_class: SierraClass,
    pub compiled_class: CompiledClass,
}

/// Parses the starknet_artifacts.json file and returns a HashMap of contract names to their artifacts
fn parse_starknet_artifacts(path: impl AsRef<Path>) -> anyhow::Result<ArtifactsMap> {
    let full_path = path.as_ref().join("target/dev");

    // Find the file that ends with starknet_artifacts.json
    let artifacts_file = std::fs::read_dir(&full_path)?
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .ends_with("starknet_artifacts.json")
        })
        .ok_or_else(|| anyhow::anyhow!("starknet_artifacts.json not found"))?;

    // Read and parse the JSON file
    let contents = std::fs::read_to_string(artifacts_file.path())?;
    let json: serde_json::Value = serde_json::from_str(&contents)?;

    let mut artifacts_map = HashMap::new();

    if let Some(contracts) = json["contracts"].as_array() {
        for contract in contracts {
            let contract_name = contract["contract_name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing contract_name in starknet_artifacts.json"))?
                .to_string();

            let sierra_path = contract["artifacts"]["sierra"]
                .as_str()
                .ok_or_else(|| {
                    anyhow::anyhow!("Missing sierra artifact for contract {}", contract_name)
                })?
                .to_string();
            let sierra_path = full_path.join(sierra_path);
            let sierra_class = std::fs::read_to_string(sierra_path).unwrap();
            let contract_class = serde_json::from_str::<SierraClass>(&sierra_class).unwrap();
            let class_hash = contract_class.class_hash()?;

            let casm_path = contract["artifacts"]["casm"]
                .as_str()
                .ok_or_else(|| {
                    anyhow::anyhow!("Missing casm artifact for contract {}", contract_name)
                })?
                .to_string();
            let casm_path = full_path.join(casm_path);
            let casm_class = std::fs::read_to_string(casm_path).unwrap();
            let compiled_class = serde_json::from_str::<CompiledClass>(&casm_class).unwrap();
            let compiled_class_hash = compiled_class.class_hash()?;

            let artifacts = Artifacts {
                class_hash,
                compiled_class_hash,
                contract_class,
                compiled_class,
            };

            artifacts_map.insert(contract_name, artifacts);
        }
    } else {
        anyhow::bail!("No contracts found in starknet_artifacts.json");
    }

    Ok(artifacts_map)
}

impl Artifacts {
    pub async fn declare_and_wait_for_receipt(
        self,
        account: Arc<StarknetWallet>,
    ) -> (Felt, Option<DeclareTransactionResult>) {
        let compiled_class_hash = self.compiled_class_hash;
        let sierra = self.contract_class.flatten().unwrap();

        let class_hash = self.class_hash;
        if account
            .provider()
            .get_class(BlockId::Tag(BlockTag::Pending), class_hash)
            .await
            .is_ok()
        {
            return (class_hash, None);
        }
        let declare_result =
            declare_contract(account.clone(), Arc::new(sierra), compiled_class_hash)
                .await
                .unwrap();
        declare_result
            .wait_for_receipt(account.provider().clone(), None)
            .await
            .unwrap();

        (self.class_hash, Some(declare_result))
    }

    pub async fn declare_and_deploy_and_wait_for_receipt(
        self,
        account: Arc<StarknetWallet>,
        constructor_calldata: Vec<Felt>,
        salt: Felt,
        unique: bool,
    ) -> Felt {
        let class_hash = self.class_hash;
        self.declare_and_wait_for_receipt(account.clone()).await;
        let (invoke_result, deployed_address) = deploy_contract(
            account.clone(),
            class_hash,
            constructor_calldata,
            salt,
            unique,
        )
        .await
        .unwrap();
        invoke_result
            .wait_for_receipt(account.provider().clone(), None)
            .await
            .unwrap();
        deployed_address
    }
}
