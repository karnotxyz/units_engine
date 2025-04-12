use std::sync::Arc;

use starknet::core::types::{
    BroadcastedDeployAccountTransaction, BroadcastedDeployAccountTransactionV3,
    DeployAccountTransactionResult,
};
use starknet::providers::{Provider, ProviderError};
use units_utils::context::GlobalContext;

pub async fn add_deploy_account_transaction(
    global_ctx: Arc<GlobalContext>,
    deploy_account_transaction: BroadcastedDeployAccountTransactionV3,
) -> Result<DeployAccountTransactionResult, ProviderError> {
    let starknet_provider = global_ctx.starknet_provider();
    starknet_provider
        .add_deploy_account_transaction(BroadcastedDeployAccountTransaction::V3(
            deploy_account_transaction,
        ))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use starknet::{
        accounts::{AccountFactory, OpenZeppelinAccountFactory},
        core::types::{
            BlockId, BlockTag, BroadcastedDeployAccountTransactionV3, DataAvailabilityMode, Felt,
            ResourceBounds, ResourceBoundsMapping,
        },
        signers::{LocalWallet, Signer, SigningKey},
    };
    use units_tests_utils::{
        madara::{madara_node, MadaraRunner},
        starknet::PREDEPLOYED_ACCOUNT_CLASS_HASH,
    };
    use units_utils::starknet::{wait_for_receipt, StarknetProvider};

    #[rstest]
    #[tokio::test]
    async fn test_add_deploy_account_transaction(
        #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
    ) {
        let (_madara_runner, starknet_provider) = madara_node.await;
        let global_ctx = Arc::new(GlobalContext::new_with_provider(starknet_provider.clone()));
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
        let prepared_deployment = account_factory
            .deploy_v3(salt)
            .gas(0)
            .gas_price(0)
            .nonce(Felt::ZERO)
            .prepared()
            .unwrap();
        let tx_hash = prepared_deployment.transaction_hash(false);
        let signature = wallet.sign_hash(&tx_hash).await.unwrap();
        let deploy_account_transaction = BroadcastedDeployAccountTransactionV3 {
            signature: vec![signature.r, signature.s],
            nonce: Felt::ZERO,
            contract_address_salt: salt,
            constructor_calldata: vec![verifying_key.scalar()],
            class_hash: Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let result = add_deploy_account_transaction(global_ctx, deploy_account_transaction)
            .await
            .unwrap();
        assert_eq!(result.transaction_hash, tx_hash);
        wait_for_receipt(starknet_provider.clone(), tx_hash, None)
            .await
            .unwrap();
        let class_hash_at = starknet_provider
            .get_class_hash_at(BlockId::Tag(BlockTag::Pending), account_address)
            .await
            .unwrap();
        assert_eq!(
            class_hash_at,
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_CLASS_HASH)
        );
    }
}
