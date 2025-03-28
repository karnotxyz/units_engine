use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use std::{path::PathBuf, process::Command};

pub static WORKSPACE_ROOT: Lazy<PathBuf> =
    Lazy::new(|| get_workspace_root().expect("Failed to get workspace root"));

fn get_workspace_root() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("Failed to run cargo metadata"));
    }

    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let workspace_root = metadata["workspace_root"]
        .as_str()
        .ok_or_else(|| anyhow!("Failed to get workspace root from cargo metadata"))?;

    Ok(PathBuf::from(workspace_root))
}
