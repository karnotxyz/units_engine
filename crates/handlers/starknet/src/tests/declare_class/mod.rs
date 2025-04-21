use assert_matches::assert_matches;
use rstest::*;
use starknet::{
    accounts::Account,
    core::types::{BlockId, BlockTag, FunctionCall},
};

use crate::utils::WaitForReceipt;
use crate::{
    tests::utils::{
        madara::{
            madara_node, madara_node_with_accounts, MadaraRunner, StarknetWalletWithPrivateKey,
        },
        scarb::{scarb_build, scarb_builds, ArtifactsMap},
        starknet::assert_contract_class_eq,
    },
    StarknetContext,
};
use crate::{StarknetProvider, StarknetWallet};
use starknet::core::types::ExecutionResult;
use starknet::macros::selector;
use std::sync::Arc;
#[cfg(feature = "testing")]
use units_primitives::read_data::{
    sign_read_data, ReadData, ReadDataVersion, ReadType, ReadValidity,
};
use units_primitives::{
    context::GlobalContext,
    read_data::{ReadVerifier, VerifierAccount},
    rpc::{DeclareProgramParams, DeclareTransactionResult},
    types::ClassVisibility,
};

use starknet::core::types::Call;
use starknet::core::types::Felt;
use starknet::providers::Provider;
use units_handlers_common::{
    declare_class::declare_class, transaction_receipt::get_transaction_receipt,
};
use units_primitives::rpc::GetTransactionReceiptParams;

use crate::tests::utils::starknet::ProviderToDummyGlobalContext;
use units_handlers_common::transaction_receipt::TransactionReceiptError;
use units_primitives::rpc::ExecutionStatus;

#[cfg(feature = "testing")]
mod tests {
    use starknet::{
        accounts::ConnectedAccount,
        core::types::{
            BroadcastedDeclareTransactionV3, DataAvailabilityMode, ResourceBounds,
            ResourceBoundsMapping,
        },
    };

    use crate::tests::utils::scarb::Artifacts;

    use super::*;

    #[rstest]
    #[tokio::test]
    async fn test_declare_class(
        #[future]
        #[with(2)]
        madara_node_with_accounts: (
            MadaraRunner,
            Arc<StarknetProvider>,
            Vec<StarknetWalletWithPrivateKey>,
        ),
    ) {
        let (_runner, provider, accounts) = madara_node_with_accounts.await;

        // Get the contract artifacts
        let mut artifacts = scarb_builds(vec![
            "src/tests/declare_class/test_contracts",
            "src/tests/get_class/test_contracts",
        ])
        .await;
        let test_contract = artifacts.remove("EmptyContract").unwrap();
        let declare_acl_contract = artifacts.remove("DeclareAclContract").unwrap();
        let declare_acl_owner: StarknetWalletWithPrivateKey = accounts[1].clone();
        let declare_acl_address = declare_acl_contract
            .declare_and_deploy_and_wait_for_receipt(
                declare_acl_owner.account.clone(),
                vec![],
                Felt::ZERO,
                false,
            )
            .await;

        // Create a starknet context with the declare ACL contract address and the account
        let starknet_ctx = StarknetContext::new_with_provider(
            provider.clone(),
            declare_acl_address.into(),
            declare_acl_owner.private_key.into(),
            declare_acl_owner.account.address().into(),
        )
        .await
        .unwrap();
        let global_ctx = Arc::new(GlobalContext::new(Arc::new(Box::new(starknet_ctx))));

        // Declare the class
        let declare_txn = build_declare_txn(accounts[0].clone(), test_contract.clone()).await;
        let result = declare_class(
            global_ctx.clone(),
            declare_txn.clone(),
            ClassVisibility::Acl,
        )
        .await
        .unwrap();
        let starknet_declare_txn = starknet::core::types::DeclareTransactionResult {
            class_hash: result.class_hash.try_into().unwrap(),
            transaction_hash: result.transaction_hash.unwrap().try_into().unwrap(),
        };
        let receipt = starknet_declare_txn
            .wait_for_receipt(provider.clone(), None)
            .await
            .unwrap();
        let txn = provider
            .get_transaction_by_hash(starknet_declare_txn.transaction_hash)
            .await
            .unwrap();

        // Verify the class was declared by retrieving it
        let declared_class = provider
            .get_class(
                BlockId::Tag(BlockTag::Pending),
                starknet_declare_txn.class_hash,
            )
            .await
            .unwrap();

        assert_contract_class_eq(
            test_contract.clone().contract_class.flatten().unwrap(),
            declared_class,
        );

        // Fetch visibility from the contract
        let visibility = provider
            .call(
                FunctionCall {
                    contract_address: global_ctx
                        .handler()
                        .get_declare_acl_address()
                        .try_into()
                        .unwrap(),
                    entry_point_selector: selector!("get_visibility"),
                    calldata: vec![starknet_declare_txn.class_hash],
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await
            .unwrap();

        assert_eq!(visibility, vec![ClassVisibility::Acl.into()]);

        // Declare again with new ACL
        let declare_txn = build_declare_txn(accounts[0].clone(), test_contract.clone()).await;
        let result = declare_class(global_ctx.clone(), declare_txn, ClassVisibility::Public)
            .await
            .unwrap();
        assert_eq!(
            result,
            DeclareTransactionResult {
                class_hash: starknet_declare_txn.class_hash.into(),
                transaction_hash: None,
                acl_updated: true,
            }
        );

        // Wait for new block number to be sure the ACL transaction is on chain
        let current_block = provider.block_number().await.unwrap();
        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(10);
        let retry_delay = std::time::Duration::from_millis(200);

        loop {
            let block = provider.block_number().await.unwrap();
            if block > current_block {
                break;
            }
            if start_time.elapsed() >= timeout {
                panic!("Block not found after {:?} timeout", timeout);
            }
            tokio::time::sleep(retry_delay).await;
        }

        // Check if ACL was updated
        let visibility = provider
            .call(
                FunctionCall {
                    contract_address: global_ctx
                        .handler()
                        .get_declare_acl_address()
                        .try_into()
                        .unwrap(),
                    entry_point_selector: selector!("get_visibility"),
                    calldata: vec![starknet_declare_txn.class_hash],
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await
            .unwrap();
        assert_eq!(visibility, vec![ClassVisibility::Public.into()]);
    }

    async fn build_declare_txn(
        account: StarknetWalletWithPrivateKey,
        artifact: Artifacts,
    ) -> DeclareProgramParams {
        let provider = account.account.provider();
        let nonce = provider
            .get_nonce(BlockId::Tag(BlockTag::Pending), account.account.address())
            .await
            .unwrap();

        let declare_tx = account
            .account
            .declare_v3(
                Arc::new(artifact.contract_class.clone().flatten().unwrap()),
                artifact.compiled_class_hash,
            )
            .gas(0)
            .gas_price(0)
            .nonce(nonce)
            .prepared()
            .unwrap();
        let tx_hash = declare_tx.transaction_hash(false);
        let signature = account.sign_message(&tx_hash);

        let flattened_contract_class = artifact.contract_class.flatten().unwrap();
        DeclareProgramParams {
            account_address: account.account.address().into(),
            signature: vec![signature.r.into(), signature.s.into()],
            nonce: nonce.try_into().unwrap(),
            program: serde_json::to_value(flattened_contract_class.clone()).unwrap(),
            compiled_program_hash: Some(artifact.compiled_class_hash.into()),
        }
    }
}
