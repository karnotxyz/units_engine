use jsonrpsee::core::{async_trait, RpcResult};
use mp_rpc::{
    BlockHashAndNumber, BlockId, ContractClass, EntryPointsByType, EventFilterWithPageRequest,
    EventsChunk, FeeEstimate, FunctionCall, InvokeTxnV0, MaybeDeprecatedContractClass, MsgFromL1,
    StarknetGetBlockWithTxsAndReceiptsResult, SyncingStatus, TxnFinalityAndExecutionStatus,
    TxnReceiptWithBlockInfo, TxnWithHash,
};
use mp_rpc::{BroadcastedTxn, SimulationFlagForEstimateFee};
use starknet_types_core::felt::Felt;

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
        _request: Vec<BroadcastedTxn>,
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
            unit: mp_rpc::PriceUnit::Wei,
        })
    }

    fn get_class_at(
        &self,
        _block_id: BlockId,
        _contract_address: Felt,
    ) -> RpcResult<MaybeDeprecatedContractClass> {
        Ok(MaybeDeprecatedContractClass::ContractClass(ContractClass {
            abi: None,
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

    fn get_class(
        &self,
        _block_id: BlockId,
        _class_hash: Felt,
    ) -> RpcResult<MaybeDeprecatedContractClass> {
        Ok(MaybeDeprecatedContractClass::ContractClass(ContractClass {
            abi: None,
            contract_class_version: "0.1.0".to_string(),
            entry_points_by_type: EntryPointsByType {
                constructor: vec![],
                external: vec![],
                l1_handler: vec![],
            },
            sierra_program: vec![],
        }))
    }

    async fn get_events(&self, _filter: EventFilterWithPageRequest) -> RpcResult<EventsChunk> {
        Ok(EventsChunk {
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
    ) -> RpcResult<TxnWithHash> {
        Ok(TxnWithHash {
            transaction: mp_rpc::Txn::Invoke(mp_rpc::InvokeTxn::V0(InvokeTxnV0 {
                calldata: vec![],
                contract_address: Felt::from(0),
                entry_point_selector: Felt::from(0),
                max_fee: Felt::from(0),
                signature: vec![],
            })),
            transaction_hash: Felt::from(0),
        })
    }

    fn get_transaction_by_hash(&self, _transaction_hash: Felt) -> RpcResult<TxnWithHash> {
        Ok(TxnWithHash {
            transaction: mp_rpc::Txn::Invoke(mp_rpc::InvokeTxn::V0(InvokeTxnV0 {
                calldata: vec![],
                contract_address: Felt::from(0),
                entry_point_selector: Felt::from(0),
                max_fee: Felt::from(0),
                signature: vec![],
            })),
            transaction_hash: Felt::from(0),
        })
    }

    async fn get_transaction_receipt(
        &self,
        _transaction_hash: Felt,
    ) -> RpcResult<TxnReceiptWithBlockInfo> {
        Ok(TxnReceiptWithBlockInfo {
            block_hash: Some(Felt::from(0)),
            block_number: Some(0),
            transaction_receipt: mp_rpc::TxnReceipt::Invoke(mp_rpc::InvokeTxnReceipt {
                common_receipt_properties: mp_rpc::CommonReceiptProperties {
                    actual_fee: mp_rpc::FeePayment {
                        amount: Felt::from(0),
                        unit: mp_rpc::PriceUnit::Wei,
                    },
                    events: vec![],
                    execution_resources: mp_rpc::ExecutionResources {
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
                    finality_status: mp_rpc::TxnFinalityStatus::L1,
                    messages_sent: vec![],
                    transaction_hash: Felt::from(0),
                    execution_status: mp_rpc::ExecutionStatus::Successful,
                },
            }),
        })
    }

    fn get_transaction_status(
        &self,
        _transaction_hash: Felt,
    ) -> RpcResult<TxnFinalityAndExecutionStatus> {
        Ok(TxnFinalityAndExecutionStatus {
            finality_status: mp_rpc::TxnStatus::AcceptedOnL1,
            execution_status: Some(mp_rpc::TxnExecutionStatus::Succeeded),
        })
    }

    async fn syncing(&self) -> RpcResult<SyncingStatus> {
        Ok(SyncingStatus::NotSyncing)
    }
}
