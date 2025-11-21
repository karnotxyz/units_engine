use std::sync::Arc;

use crate::tests::utils::{
    madara::{madara_node, MadaraRunner},
    starknet::{fund_account_devnet, ProviderToDummyGlobalContext, PREDEPLOYED_ACCOUNT_CLASS_HASH},
};
use crate::utils::wait_for_receipt;
use crate::StarknetProvider;
use rstest::*;
use starknet::{
    accounts::{AccountFactory, OpenZeppelinAccountFactory},
    core::types::{BlockId, BlockTag, Felt},
    providers::Provider,
    signers::{LocalWallet, Signer, SigningKey},
};
use units_handlers_common::deploy_account::deploy_account;
use units_primitives::rpc::DeployAccountParams;

#[rstest]
#[tokio::test]
async fn test_add_deploy_account_transaction(
    #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
) {
    let (_madara_runner, starknet_provider) = madara_node.await;
    let global_ctx = starknet_provider.provider_to_dummy_global_context().await;
    let chain_id = starknet_provider.chain_id().await.unwrap();
    let signer = SigningKey::from_secret_scalar(Felt::ONE);
    let verifying_key = signer.verifying_key();
    let wallet = Arc::new(LocalWallet::from(signer));
    let account_factory = OpenZeppelinAccountFactory::new(
        Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH),
        chain_id,
        wallet.clone(),
        starknet_provider.clone(),
    )
    .await
    .unwrap();
    let salt = Felt::ONE;
    let account_address = account_factory.deploy_v3(salt).address();
    let fee_estimate = account_factory
        .deploy_v3(salt)
        .nonce(Felt::ZERO)
        .estimate_fee()
        .await
        .unwrap();
    let prepared_deployment = account_factory
        .deploy_v3(salt)
        .nonce(Felt::ZERO)
        .l1_gas_price(fee_estimate.l1_gas_price)
        .l1_gas(fee_estimate.l1_gas_consumed)
        .l2_gas_price(fee_estimate.l2_gas_price)
        .l2_gas(fee_estimate.l2_gas_consumed)
        .l1_data_gas_price(fee_estimate.l1_data_gas_price)
        .l1_data_gas(fee_estimate.l1_data_gas_consumed)
        .tip(0)
        .prepared()
        .unwrap();
    let tx_hash = prepared_deployment.transaction_hash(false);
    let signature = wallet.sign_hash(&tx_hash).await.unwrap();
    let deploy_account_transaction = DeployAccountParams {
        signature: vec![signature.r.into(), signature.s.into()],
        nonce: Felt::ZERO.try_into().unwrap(),
        account_address_salt: salt.into(),
        constructor_calldata: vec![verifying_key.scalar().into()],
        program_hash: Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH).into(),
        resource_bounds: fee_estimate.into(),
    };

    fund_account_devnet(starknet_provider.clone(), account_address)
        .await
        .unwrap();
    let result = deploy_account(global_ctx, deploy_account_transaction)
        .await
        .unwrap();
    assert_eq!(result.transaction_hash, tx_hash.into());
    wait_for_receipt(starknet_provider.clone(), tx_hash, None)
        .await
        .unwrap();
    let class_hash_at = starknet_provider
        .get_class_hash_at(BlockId::Tag(BlockTag::PreConfirmed), account_address)
        .await
        .unwrap();
    assert_eq!(
        class_hash_at,
        Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH)
    );
}
