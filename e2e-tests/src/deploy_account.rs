
use rstest::*;


#[tokio::test]
#[rstest]
async fn test_deploy_account_works(
    #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
) -> Result<()> {
    let (_runner, provider) = madara_node.await;

    // Deploy a dummy account and asserts on receipt
    let wallet = deploy_dummy_account(provider.clone()).await?;

    let nonce = provider
        .get_nonce(BlockId::Tag(BlockTag::Pending), wallet.address())
        .await
        .unwrap();
    assert_eq!(nonce, Felt::ONE);

    Ok(())
}
