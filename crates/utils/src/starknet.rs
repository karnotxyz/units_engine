use std::{any, sync::Arc};

use starknet::{
    core::types::{
        BlockId, ContractClass, ExecuteInvocation, FeeEstimate, Felt, PriceUnit,
        SimulatedTransaction, TransactionTrace,
    },
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError},
};

pub type StarknetProvider = JsonRpcClient<HttpTransport>;

pub async fn get_contract_class(
    starknet_provider: Arc<StarknetProvider>,
    contract_address: Felt,
    block_id: BlockId,
) -> Result<ContractClass, ProviderError> {
    starknet_provider
        .get_class_at(block_id, contract_address)
        .await
}

pub async fn contract_class_has_selector(contract_class: ContractClass, selector: Felt) -> bool {
    match contract_class {
        ContractClass::Sierra(sierra_class) => sierra_class
            .entry_points_by_type
            .external
            .iter()
            .any(|entry_point| entry_point.selector == selector),
        ContractClass::Legacy(legacy_class) => legacy_class
            .entry_points_by_type
            .external
            .iter()
            .any(|entry_point| entry_point.selector == selector),
    }
}

pub async fn contract_address_has_selector(
    starknet_provider: Arc<StarknetProvider>,
    contract_address: Felt,
    block_id: BlockId,
    selector: Felt,
) -> Result<bool, ProviderError> {
    let contract_class = get_contract_class(starknet_provider, contract_address, block_id).await?;
    Ok(contract_class_has_selector(contract_class, selector).await)
}

pub trait GetExecutionResult {
    fn get_execution_result(&self) -> anyhow::Result<ExecuteInvocation>;
}

impl GetExecutionResult for SimulatedTransaction {
    fn get_execution_result(&self) -> anyhow::Result<ExecuteInvocation> {
        match &self.transaction_trace {
            TransactionTrace::Invoke(invoke_transaction) => {
                Ok(invoke_transaction.execute_invocation.clone())
            }
            TransactionTrace::Declare(_) => {
                anyhow::bail!("Declare transactions don't have execution results")
            }
            TransactionTrace::DeployAccount(_) => {
                anyhow::bail!("Deploy account transactions don't have execution results")
            }
            TransactionTrace::L1Handler(l1_handler_transaction) => {
                // L1 Handler transactions won't exist on the chain if they failed
                Ok(ExecuteInvocation::Success(
                    l1_handler_transaction.function_invocation.clone(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use starknet::{
        core::types::{BlockTag, CallType, EntryPointType, InvokeTransactionTrace, RevertedInvocation},
        macros::selector,
    };
    use units_tests_utils::{
        madara::{madara_node, MadaraRunner},
        starknet::{
            build_declare_trace, build_deploy_account_trace, build_function_invocation,
            build_l1_handler_trace, PREDEPLOYED_ACCOUNT_ADDRESS, build_execution_resources
        },
    };

    #[rstest]
    #[tokio::test]
    async fn test_get_contract_class(#[future] madara_node: (MadaraRunner, Arc<StarknetProvider>)) {
        let (_runner, provider) = madara_node.await;

        // Get the contract class of the predeployed account
        match get_contract_class(
            provider.clone(),
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                panic!("Failed to get contract class: {:?}", e);
            }
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_contract_class_has_selector(
        #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
    ) {
        let (_runner, provider) = madara_node.await;

        // Get the contract class of the predeployed account
        let contract_class = get_contract_class(
            provider.clone(),
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .unwrap();

        // Test that __execute__ selector exists
        let execute_selector = selector!("__execute__");
        assert!(contract_class_has_selector(contract_class.clone(), execute_selector).await);

        // Test that a random selector doesn't exist
        let random_selector = Felt::from_hex_unchecked("0xbad");
        assert!(!contract_class_has_selector(contract_class, random_selector).await);
    }

    #[rstest]
    #[tokio::test]
    async fn test_contract_address_has_selector(
        #[future] madara_node: (MadaraRunner, Arc<StarknetProvider>),
    ) {
        let (_runner, provider) = madara_node.await;

        // Test that __execute__ selector exists
        let execute_selector = selector!("__execute__");
        assert!(contract_address_has_selector(
            provider.clone(),
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
            BlockId::Tag(BlockTag::Latest),
            execute_selector
        )
        .await
        .unwrap());

        // Test that a random selector doesn't exist
        let random_selector = Felt::from_hex_unchecked("0xbad");
        assert!(!contract_address_has_selector(
            provider.clone(),
            Felt::from_hex_unchecked(PREDEPLOYED_ACCOUNT_ADDRESS),
            BlockId::Tag(BlockTag::Latest),
            random_selector
        )
        .await
        .unwrap());
    }

    #[rstest]
    #[case::success(ExecuteInvocation::Success(build_function_invocation()))]
    #[case::reverted(
        ExecuteInvocation::Reverted(RevertedInvocation {
            revert_reason: "Transaction reverted".into(),
        })
    )]
    fn test_get_execution_result_invoke(#[case] execute_invocation: ExecuteInvocation) {
        let trace = TransactionTrace::Invoke(InvokeTransactionTrace {
            validate_invocation: None,
            execute_invocation: execute_invocation.clone(),
            fee_transfer_invocation: None,
            state_diff: None,
            execution_resources: build_execution_resources(),
        });

        let simulated_transaction = SimulatedTransaction {
            transaction_trace: trace,
            fee_estimation: FeeEstimate {
                gas_consumed: 0.into(),
                gas_price: 0.into(),
                data_gas_consumed: 0.into(),
                data_gas_price: 0.into(),
                overall_fee: 0.into(),
                unit: PriceUnit::Wei,
            },
        };

        let result = simulated_transaction.get_execution_result();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), execute_invocation);
    }

    #[test]
    fn test_get_execution_result_declare() {
        let trace = TransactionTrace::Declare(build_declare_trace());
        let simulated_transaction = SimulatedTransaction {
            transaction_trace: trace,
            fee_estimation: FeeEstimate {
                gas_consumed: 0.into(),
                gas_price: 0.into(),
                data_gas_consumed: 0.into(),
                data_gas_price: 0.into(),
                overall_fee: 0.into(),
                unit: PriceUnit::Wei,
            },
        };

        let result = simulated_transaction.get_execution_result();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Declare transactions don't have execution results"
        );
    }

    #[test]
    fn test_get_execution_result_deploy_account() {
        let trace = TransactionTrace::DeployAccount(build_deploy_account_trace());
        let simulated_transaction = SimulatedTransaction {
            transaction_trace: trace,
            fee_estimation: FeeEstimate {
                gas_consumed: 0.into(),
                gas_price: 0.into(),
                data_gas_consumed: 0.into(),
                data_gas_price: 0.into(),
                overall_fee: 0.into(),
                unit: PriceUnit::Wei,
            },
        };

        let result = simulated_transaction.get_execution_result();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Deploy account transactions don't have execution results"
        );
    }

    #[test]
    fn test_get_execution_result_l1_handler() {
        let l1_handler_trace = build_l1_handler_trace();
        let function_invocation = l1_handler_trace.function_invocation.clone();
        let trace = TransactionTrace::L1Handler(l1_handler_trace);
        let simulated_transaction = SimulatedTransaction {
            transaction_trace: trace,
            fee_estimation: FeeEstimate {
                gas_consumed: 0.into(),
                gas_price: 0.into(),
                data_gas_consumed: 0.into(),
                data_gas_price: 0.into(),
                overall_fee: 0.into(),
                unit: PriceUnit::Wei,
            },
        };

        let result = simulated_transaction.get_execution_result();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExecuteInvocation::Success(function_invocation));
    }
}
