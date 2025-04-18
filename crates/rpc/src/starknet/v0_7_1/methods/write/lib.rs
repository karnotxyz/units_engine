use crate::{
    starknet::{errors::StarknetRpcApiError, v0_7_1::StarknetWriteRpcApiV0_7_1Server},
    RpcContext,
};
use jsonrpsee::core::{async_trait, RpcResult};
use starknet::{
    core::types::{
        BroadcastedDeclareTransaction, BroadcastedDeployAccountTransaction,
        BroadcastedInvokeTransaction, DeclareTransactionResult, DeployAccountTransactionResult,
        Felt, InvokeTransactionResult,
    },
    providers::ProviderError,
};
use units_primitives::types::ClassVisibility;

#[async_trait]
impl StarknetWriteRpcApiV0_7_1Server for RpcContext {
    /// Submit a new declare transaction to be added to the chain
    ///
    /// # Arguments
    ///
    /// * `declare_transaction` - the declare transaction to be added to the chain
    ///
    /// # Returns
    ///
    /// * `declare_transaction_result` - the result of the declare transaction
    async fn add_declare_transaction(
        &self,
        declare_transaction: BroadcastedDeclareTransaction,
    ) -> RpcResult<DeclareTransactionResult> {
        let declare_transaction = match declare_transaction {
            BroadcastedDeclareTransaction::V3(declare_transaction) => declare_transaction,
            _ => {
                return Err(StarknetRpcApiError::UnsupportedTxnVersion.into());
            }
        };
        let result = units_handlers::declare_class::add_declare_class_transaction(
            self.global_ctx.clone(),
            declare_transaction,
            ClassVisibility::Public,
        )
        .await
        .map_err(ProviderError::from)
        .map_err(StarknetRpcApiError::from)?;

        // It's possible that the transaction hash is not available as the class
        // was already declared.
        let transaction_hash = if let Some(transaction_hash) = result.transaction_hash {
            transaction_hash
        } else {
            return Err(StarknetRpcApiError::ClassAlreadyDeclared.into());
        };

        // Convert Strings to Felts
        let class_hash = Felt::from_hex(result.class_hash.as_str()).map_err(|e| {
            StarknetRpcApiError::ErrUnexpectedError {
                data: format!("Failed to convert class hash to felt: {}", e),
            }
        })?;
        let transaction_hash = Felt::from_hex(transaction_hash.as_str()).map_err(|e| {
            StarknetRpcApiError::ErrUnexpectedError {
                data: format!("Failed to convert transaction hash to felt: {}", e),
            }
        })?;

        Ok(DeclareTransactionResult {
            class_hash,
            transaction_hash,
        })
    }

    /// Add an Deploy Account Transaction
    ///
    /// # Arguments
    ///
    /// * `deploy account transaction` - <https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#deploy_account_transaction>
    ///
    /// # Returns
    ///
    /// * `transaction_hash` - transaction hash corresponding to the invocation
    /// * `contract_address` - address of the deployed contract account
    async fn add_deploy_account_transaction(
        &self,
        deploy_account_transaction: BroadcastedDeployAccountTransaction,
    ) -> RpcResult<DeployAccountTransactionResult> {
        let deploy_account_transaction = match deploy_account_transaction {
            BroadcastedDeployAccountTransaction::V3(deploy_account_transaction) => {
                deploy_account_transaction
            }
            _ => {
                return Err(StarknetRpcApiError::UnsupportedTxnVersion.into());
            }
        };
        Ok(
            units_handlers::deploy_account::add_deploy_account_transaction(
                self.global_ctx.clone(),
                deploy_account_transaction,
            )
            .await
            .map_err(StarknetRpcApiError::from)?,
        )
    }

    /// Add an Invoke Transaction to invoke a contract function
    ///
    /// # Arguments
    ///
    /// * `invoke tx` - <https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/#invoke_transaction>
    ///
    /// # Returns
    ///
    /// * `transaction_hash` - transaction hash corresponding to the invocation
    async fn add_invoke_transaction(
        &self,
        _invoke_transaction: BroadcastedInvokeTransaction,
    ) -> RpcResult<InvokeTransactionResult> {
        Ok(InvokeTransactionResult {
            transaction_hash: Felt::from(0),
        })
    }
}
