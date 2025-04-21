use std::sync::Arc;

use rstest::*;
use serde_json::{json, Value};
use units_handlers_starknet::{
    tests::utils::madara::{madara_node, MadaraRunner},
    StarknetProvider,
};
use units_primitives::rpc::{GetChainIdResult, HexBytes32};
use units_tests_utils::units::UnitsRunner;

#[tokio::test]
#[rstest]
async fn test_chain_id(
    #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
) -> anyhow::Result<()> {
    let (madara_runner, _) = madara_node.await;
    println!("Madara URL: {}", madara_runner.rpc_url().unwrap());
    let mut runner = UnitsRunner::new(madara_runner)?;
    runner.run().await?;
    let url = runner.rpc_url().unwrap();

    println!("Units URL: {}", url);

    // Make JSON-RPC request to get chain ID
    let client = reqwest::Client::new();
    let response: Value = client
        .post(url.to_string())
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "units_getChainId",
            "params": [],
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;

    let parsed_response: GetChainIdResult = serde_json::from_value(response["result"].clone())?;
    // Verify the chain ID is MADARA_DEVNET
    assert_eq!(
        parsed_response.chain_id,
        HexBytes32::from_hex("0x4d41444152415f4445564e4554").unwrap()
    );

    Ok(())
}
