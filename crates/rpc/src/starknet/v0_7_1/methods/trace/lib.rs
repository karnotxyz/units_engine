use crate::{starknet::v0_7_1::StarknetTraceRpcApiV0_7_1Server, RpcContext};
use jsonrpsee::core::{async_trait, RpcResult};
use mp_rpc::{
    BlockId, BroadcastedTxn, ComputationResources, ExecutionResources, FunctionCall,
    FunctionInvocation, InvokeTransactionTrace, SimulateTransactionsResult, SimulationFlag,
    TraceBlockTransactionsResult, TransactionTrace,
};
use starknet_types_core::felt::Felt;

#[async_trait]
impl StarknetTraceRpcApiV0_7_1Server for RpcContext {
    async fn simulate_transactions(
        &self,
        block_id: BlockId,
        transactions: Vec<BroadcastedTxn>,
        simulation_flags: Vec<SimulationFlag>,
    ) -> RpcResult<Vec<SimulateTransactionsResult>> {
        Ok(vec![])
    }

    async fn trace_transaction(
        &self,
        transaction_hash: Felt,
    ) -> RpcResult<TraceBlockTransactionsResult> {
        Ok(TraceBlockTransactionsResult {
            transaction_hash,
            trace_root: TransactionTrace::Invoke(InvokeTransactionTrace {
                execute_invocation: mp_rpc::ExecuteInvocation::FunctionInvocation(
                    FunctionInvocation {
                        function_call: FunctionCall {
                            calldata: vec![],
                            contract_address: Felt::from(0),
                            entry_point_selector: Felt::from(0),
                        },
                        call_type: mp_rpc::CallType::Regular,
                        caller_address: Felt::from(0),
                        calls: vec![],
                        class_hash: Felt::from(0),
                        entry_point_type: mp_rpc::EntryPointType::External,
                        events: vec![],
                        execution_resources: ComputationResources {
                            bitwise_builtin_applications: None,
                            ec_op_builtin_applications: None,
                            ecdsa_builtin_applications: None,
                            keccak_builtin_applications: None,
                            memory_holes: None,
                            pedersen_builtin_applications: None,
                            poseidon_builtin_applications: None,
                            range_check_builtin_applications: None,
                            segment_arena_builtin: None,
                            steps: 0,
                        },
                        messages: vec![],
                        result: vec![],
                    },
                ),
                execution_resources: ExecutionResources {
                    bitwise_builtin_applications: None,
                    ec_op_builtin_applications: None,
                    ecdsa_builtin_applications: None,
                    keccak_builtin_applications: None,
                    memory_holes: None,
                    pedersen_builtin_applications: None,
                    poseidon_builtin_applications: None,
                    range_check_builtin_applications: None,
                    segment_arena_builtin: None,
                    steps: 0,
                    data_availability: mp_rpc::DataAvailability {
                        l1_data_gas: 0,
                        l1_gas: 0,
                    },
                },
                fee_transfer_invocation: None,
                state_diff: None,
                validate_invocation: None,
            }),
        })
    }
}
