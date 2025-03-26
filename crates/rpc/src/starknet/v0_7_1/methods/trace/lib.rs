use crate::{starknet::v0_7_1::StarknetTraceRpcApiV0_7_1Server, RpcContext};
use jsonrpsee::core::{async_trait, RpcResult};
use starknet::core::types::{
    BlockId, BroadcastedTransaction, ComputationResources, DataAvailabilityResources,
    DataResources, ExecuteInvocation, ExecutionResources, Felt, FunctionCall, FunctionInvocation,
    InvokeTransactionTrace, SimulatedTransaction, SimulationFlag, TransactionTrace,
};

#[async_trait]
impl StarknetTraceRpcApiV0_7_1Server for RpcContext {
    async fn simulate_transactions(
        &self,
        block_id: BlockId,
        transactions: Vec<BroadcastedTransaction>,
        simulation_flags: Vec<SimulationFlag>,
    ) -> RpcResult<Vec<SimulatedTransaction>> {
        Ok(vec![])
    }

    async fn trace_transaction(&self, transaction_hash: Felt) -> RpcResult<TransactionTrace> {
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
                execution_resources: ComputationResources {
                    steps: 0,
                    memory_holes: None,
                    range_check_builtin_applications: None,
                    pedersen_builtin_applications: None,
                    poseidon_builtin_applications: None,
                    ec_op_builtin_applications: None,
                    ecdsa_builtin_applications: None,
                    bitwise_builtin_applications: None,
                    keccak_builtin_applications: None,
                    segment_arena_builtin: None,
                },
            }),
            fee_transfer_invocation: None,
            state_diff: None,
            execution_resources: ExecutionResources {
                computation_resources: ComputationResources {
                    steps: 0,
                    memory_holes: None,
                    range_check_builtin_applications: None,
                    pedersen_builtin_applications: None,
                    poseidon_builtin_applications: None,
                    ec_op_builtin_applications: None,
                    ecdsa_builtin_applications: None,
                    bitwise_builtin_applications: None,
                    keccak_builtin_applications: None,
                    segment_arena_builtin: None,
                },
                data_resources: DataResources {
                    data_availability: DataAvailabilityResources {
                        l1_gas: 0,
                        l1_data_gas: 0,
                    },
                },
            },
        }))
    }
}
