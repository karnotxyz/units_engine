use jsonrpsee::core::{async_trait, RpcResult};
use starknet::core::types::{
    BlockHashAndNumber, BlockId, BroadcastedTransaction, ComputationResources, ContractClass,
    DataAvailabilityResources, DataResources, EntryPointsByType, EventFilterWithPage, EventsChunk,
    EventsPage, ExecutionResources, ExecutionResult, FeeEstimate, FeePayment, Felt,
    FlattenedSierraClass, FunctionCall, InvokeTransactionReceipt, InvokeTransactionV1, MsgFromL1,
    PriceUnit, ReceiptBlock, SimulationFlagForEstimateFee, SyncStatusType, Transaction,
    TransactionReceiptWithBlockInfo, TransactionStatus,
};

use crate::starknet::v0_7_1::StarknetReadRpcApiV0_7_1Server;
use crate::RpcContext;

#[async_trait]
impl StarknetReadRpcApiV0_7_1Server for RpcContext {
    fn spec_version(&self) -> RpcResult<String> {
        Ok("0.7.1".to_string())
    }

    fn block_number(&self) -> RpcResult<u64> {
        Ok(0)
    }

    fn block_hash_and_number(&self) -> RpcResult<BlockHashAndNumber> {
        Ok(BlockHashAndNumber {
            block_hash: Felt::from(0),
            block_number: 0,
        })
    }

    fn call(&self, _request: FunctionCall, _block_id: BlockId) -> RpcResult<Vec<Felt>> {
        Ok(vec![])
    }

    fn chain_id(&self) -> RpcResult<Felt> {
        Ok(Felt::from(1))
    }

    async fn estimate_fee(
        &self,
        _request: Vec<BroadcastedTransaction>,
        _simulation_flags: Vec<SimulationFlagForEstimateFee>,
        _block_id: BlockId,
    ) -> RpcResult<Vec<FeeEstimate>> {
        Ok(vec![])
    }

    async fn estimate_message_fee(
        &self,
        _message: MsgFromL1,
        _block_id: BlockId,
    ) -> RpcResult<FeeEstimate> {
        Ok(FeeEstimate {
            gas_consumed: Felt::from(0),
            gas_price: Felt::from(0),
            overall_fee: Felt::from(0),
            data_gas_consumed: Felt::from(0),
            data_gas_price: Felt::from(0),
            unit: starknet::core::types::PriceUnit::Wei,
        })
    }

    fn get_class_at(
        &self,
        _block_id: BlockId,
        _contract_address: Felt,
    ) -> RpcResult<ContractClass> {
        Ok(ContractClass::Sierra(FlattenedSierraClass {
            abi: "".to_string(),
            contract_class_version: "0.1.0".to_string(),
            entry_points_by_type: EntryPointsByType {
                constructor: vec![],
                external: vec![],
                l1_handler: vec![],
            },
            sierra_program: vec![],
        }))
    }

    fn get_class_hash_at(&self, _block_id: BlockId, _contract_address: Felt) -> RpcResult<Felt> {
        Ok(Felt::from(0))
    }

    fn get_class(&self, _block_id: BlockId, _class_hash: Felt) -> RpcResult<ContractClass> {
        Ok(ContractClass::Sierra(FlattenedSierraClass {
            abi: "".to_string(),
            contract_class_version: "0.1.0".to_string(),
            entry_points_by_type: EntryPointsByType {
                constructor: vec![],
                external: vec![],
                l1_handler: vec![],
            },
            sierra_program: vec![],
        }))
    }

    async fn get_events(&self, _filter: EventFilterWithPage) -> RpcResult<EventsPage> {
        Ok(EventsPage {
            events: vec![],
            continuation_token: None,
        })
    }

    fn get_nonce(&self, _block_id: BlockId, _contract_address: Felt) -> RpcResult<Felt> {
        Ok(Felt::from(0))
    }

    fn get_transaction_by_block_id_and_index(
        &self,
        _block_id: BlockId,
        _index: u64,
    ) -> RpcResult<Transaction> {
        Ok(Transaction::Invoke(
            starknet::core::types::InvokeTransaction::V1(InvokeTransactionV1 {
                calldata: vec![],
                max_fee: Felt::from(0),
                signature: vec![],
                transaction_hash: Felt::from(0),
                sender_address: Felt::from(0),
                nonce: Felt::from(0),
            }),
        ))
    }

    fn get_transaction_by_hash(&self, _transaction_hash: Felt) -> RpcResult<Transaction> {
        Ok(Transaction::Invoke(
            starknet::core::types::InvokeTransaction::V1(InvokeTransactionV1 {
                calldata: vec![],
                max_fee: Felt::from(0),
                signature: vec![],
                transaction_hash: Felt::from(0),
                sender_address: Felt::from(0),
                nonce: Felt::from(0),
            }),
        ))
    }

    async fn get_transaction_receipt(
        &self,
        _transaction_hash: Felt,
    ) -> RpcResult<TransactionReceiptWithBlockInfo> {
        Ok(TransactionReceiptWithBlockInfo {
            receipt: starknet::core::types::TransactionReceipt::Invoke(InvokeTransactionReceipt {
                transaction_hash: Felt::from(0),
                actual_fee: FeePayment {
                    amount: Felt::from(0),
                    unit: PriceUnit::Wei,
                },
                finality_status: starknet::core::types::TransactionFinalityStatus::AcceptedOnL1,
                messages_sent: vec![],
                events: vec![],
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
                execution_result: ExecutionResult::Succeeded,
            }),
            block: ReceiptBlock::Pending,
        })
    }

    fn get_transaction_status(&self, _transaction_hash: Felt) -> RpcResult<TransactionStatus> {
        Ok(TransactionStatus::Received)
    }

    async fn syncing(&self) -> RpcResult<SyncStatusType> {
        Ok(SyncStatusType::NotSyncing)
    }
}
