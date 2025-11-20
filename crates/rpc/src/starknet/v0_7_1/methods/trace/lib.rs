use crate::{starknet::v0_7_1::StarknetTraceRpcApiV0_7_1Server, RpcContext};
use jsonrpsee::core::{async_trait, RpcResult};
use starknet::core::types::{
    BlockId, BroadcastedTransaction, ExecuteInvocation, ExecutionResources, Felt,
    FunctionInvocation, InnerCallExecutionResources, InvokeTransactionTrace, SimulatedTransaction,
    SimulationFlag, TransactionTrace,
};

#[async_trait]
impl StarknetTraceRpcApiV0_7_1Server for RpcContext {
    async fn simulate_transactions(
        &self,
        _block_id: BlockId,
        _transactions: Vec<BroadcastedTransaction>,
        _simulation_flags: Vec<SimulationFlag>,
    ) -> RpcResult<Vec<SimulatedTransaction>> {
        Ok(vec![])
    }

    async fn trace_transaction(&self, _transaction_hash: Felt) -> RpcResult<TransactionTrace> {
        Ok(TransactionTrace::Invoke(InvokeTransactionTrace {
            validate_invocation: None,
            execute_invocation: ExecuteInvocation::Success(FunctionInvocation {
                contract_address: Felt::from(0),
                entry_point_selector: Felt::from(0),
                calldata: vec![],
                caller_address: Felt::from(0),
                class_hash: Felt::from(0),
                entry_point_type: starknet::core::types::EntryPointType::External,
                call_type: starknet::core::types::CallType::Call,
                result: vec![],
                calls: vec![],
                events: vec![],
                messages: vec![],
                execution_resources: InnerCallExecutionResources {
                    l1_gas: 0,
                    l2_gas: 0,
                },
                is_reverted: false,
            }),
            fee_transfer_invocation: None,
            state_diff: None,
            execution_resources: ExecutionResources {
                l1_gas: 0,
                l1_data_gas: 0,
                l2_gas: 0,
            },
        }))
    }
}
