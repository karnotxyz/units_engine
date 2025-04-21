use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use starknet::{
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount},
    core::{
        types::{
            BlockId, BlockTag, BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV3,
            BroadcastedDeployAccountTransaction, BroadcastedDeployAccountTransactionV3,
            BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV3, Call,
            DataAvailabilityMode, ExecutionResult, Felt, FlattenedSierraClass, FunctionCall,
            ResourceBounds, ResourceBoundsMapping, TransactionFinalityStatus,
        },
        utils::get_selector_from_name,
    },
    macros::selector,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, Url},
    signers::{LocalWallet, SigningKey},
};
use units_primitives::{
    context::{ChainHandler, ChainHandlerError},
    rpc::{Event, ExecutionStatus, FinalityStatus, GetTransactionByHashResult},
    types::ClassVisibilityError,
};
use units_primitives::{
    rpc::{
        DeclareProgramParams, DeployAccountParams, DeployAccountResult, GetProgramResult,
        GetTransactionReceiptResult, HexBytes32, SendTransactionParams, SendTransactionResult,
    },
    types::ClassVisibility,
};
use utils::{
    contract_address_has_selector, simulate_boolean_read, GetSenderAddress, ToFelt, WaitForReceipt,
};

#[cfg(any(test, feature = "testing"))]
pub mod tests;
pub mod utils;

pub type StarknetProvider = JsonRpcClient<HttpTransport>;
pub type StarknetWallet = SingleOwnerAccount<Arc<StarknetProvider>, Arc<LocalWallet>>;

const IS_VALID_SIGNATURE_SELECTOR: Felt = selector!("is_valid_signature");
const GET_KEY_SELECTOR: Felt = selector!("get_key");

pub struct StarknetContext {
    starknet_provider: Arc<StarknetProvider>,
    declare_acl_address: Felt,
    owner_wallet: Arc<StarknetWallet>,
}

impl StarknetContext {
    pub async fn new(
        madara_rpc_url: Url,
        declare_acl_address: HexBytes32,
        owner_private_key: HexBytes32,
        account_address: HexBytes32,
    ) -> anyhow::Result<Self> {
        let starknet_provider = JsonRpcClient::new(HttpTransport::new(madara_rpc_url));
        Self::new_with_provider(
            Arc::new(starknet_provider),
            declare_acl_address,
            owner_private_key,
            account_address,
        )
        .await
    }

    pub async fn new_with_provider(
        starknet_provider: Arc<StarknetProvider>,
        declare_acl_address: HexBytes32,
        owner_private_key: HexBytes32,
        account_address: HexBytes32,
    ) -> anyhow::Result<Self> {
        let signer = SigningKey::from_secret_scalar(
            Felt::from_hex(owner_private_key.to_hex().as_str())
                .context("Owner private key is not valid")?,
        );
        let local_wallet = Arc::new(LocalWallet::from(signer));
        let chain_id = starknet_provider
            .chain_id()
            .await
            .context("Failed to get chain id")?;
        let account_address = Felt::from_hex(account_address.to_hex().as_str())
            .context("Account address is not valid")?;
        let account = SingleOwnerAccount::new(
            starknet_provider.clone(),
            local_wallet,
            account_address,
            chain_id,
            ExecutionEncoding::New,
        );
        Ok(Self {
            starknet_provider,
            declare_acl_address: declare_acl_address.try_into()?,
            owner_wallet: Arc::new(account),
        })
    }

    pub fn starknet_provider(&self) -> Arc<StarknetProvider> {
        self.starknet_provider.clone()
    }

    pub fn declare_acl_address(&self) -> Felt {
        self.declare_acl_address
    }

    pub fn owner_wallet(&self) -> Arc<StarknetWallet> {
        self.owner_wallet.clone()
    }
}

#[async_trait]
impl ChainHandler for StarknetContext {
    async fn declare_program(
        &self,
        params: DeclareProgramParams,
    ) -> Result<HexBytes32, ChainHandlerError> {
        let class: FlattenedSierraClass = serde_json::from_value(params.program.clone())
            .map_err(|e| ChainHandlerError::InvalidProgram(e.to_string()))?;
        let declare_class_transaction = BroadcastedDeclareTransactionV3 {
            sender_address: params.account_address.to_felt()?,
            compiled_class_hash: params
                .compiled_program_hash
                .ok_or(ChainHandlerError::BadRequest(
                    "Compiled program hash is required".to_string(),
                ))?
                .to_felt()?,
            nonce: params.nonce.into(),
            contract_class: Arc::new(class),
            signature: params.signature.to_felt()?,
            account_deployment_data: vec![],
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

        let result = self
            .starknet_provider
            .add_declare_transaction(BroadcastedDeclareTransaction::V3(declare_class_transaction))
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;
        Ok(result.transaction_hash.into())
    }

    async fn send_transaction(
        &self,
        params: SendTransactionParams,
    ) -> Result<SendTransactionResult, ChainHandlerError> {
        let send_transaction_transaction = BroadcastedInvokeTransactionV3 {
            sender_address: params.account_address.to_felt()?,
            calldata: params.calldata.to_felt()?,
            nonce: params.nonce.into(),
            signature: params.signature.to_felt()?,
            account_deployment_data: vec![],
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

        let result = self
            .starknet_provider
            .add_invoke_transaction(BroadcastedInvokeTransaction::V3(
                send_transaction_transaction,
            ))
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;

        Ok(SendTransactionResult {
            transaction_hash: result.transaction_hash.into(),
        })
    }

    async fn deploy_account(
        &self,
        params: DeployAccountParams,
    ) -> Result<DeployAccountResult, ChainHandlerError> {
        let deploy_account_transaction = BroadcastedDeployAccountTransactionV3 {
            signature: params.signature.to_felt()?,
            nonce: params.nonce.into(),
            contract_address_salt: params.account_address_salt.to_felt()?,
            constructor_calldata: params.constructor_calldata.to_felt()?,
            class_hash: params.program_hash.to_felt()?,
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
        let result = self
            .starknet_provider
            .add_deploy_account_transaction(BroadcastedDeployAccountTransaction::V3(
                deploy_account_transaction,
            ))
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;
        Ok(DeployAccountResult {
            transaction_hash: result.transaction_hash.into(),
            account_address: result.contract_address.into(),
        })
    }

    async fn get_program(
        &self,
        class_hash: HexBytes32,
    ) -> Result<GetProgramResult, ChainHandlerError> {
        match self
            .starknet_provider
            .get_class(BlockId::Tag(BlockTag::Pending), class_hash.to_felt()?)
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))
        {
            Ok(program) => Ok(GetProgramResult {
                program: serde_json::to_value(&program)
                    .map_err(|e| ChainHandlerError::ConversionError(e.to_string()))?,
            }),
            Err(e) => Err(ChainHandlerError::ProgramNotFound(e.to_string())),
        }
    }

    async fn get_nonce(&self, address: HexBytes32) -> Result<u32, ChainHandlerError> {
        let nonce = self
            .starknet_provider
            .get_nonce(BlockId::Tag(BlockTag::Pending), address.to_felt()?)
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;
        Ok(nonce.try_into().map_err(|_| {
            ChainHandlerError::ConversionError("Failed to convert nonce to u64".to_string())
        })?)
    }

    async fn get_transaction_receipt(
        &self,
        transaction_hash: HexBytes32,
    ) -> Result<GetTransactionReceiptResult, ChainHandlerError> {
        let receipt = self
            .starknet_provider
            .get_transaction_receipt(transaction_hash.to_felt()?)
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;

        let events = receipt
            .receipt
            .events()
            .iter()
            .map(|event| Event {
                from_address: event.from_address.into(),
                keys: event.keys.iter().map(|key| (*key).into()).collect(),
                data: event.data.iter().map(|data| (*data).into()).collect(),
            })
            .collect();

        let finality_status = match receipt.receipt.finality_status() {
            TransactionFinalityStatus::AcceptedOnL2 => FinalityStatus::AcceptedOnUnits,
            TransactionFinalityStatus::AcceptedOnL1 => FinalityStatus::AcceptedOnProofStore,
        };

        let execution_status = match receipt.receipt.execution_result() {
            ExecutionResult::Succeeded => ExecutionStatus::Succeeded,
            ExecutionResult::Reverted { reason } => ExecutionStatus::Reverted {
                error: reason.to_string(),
            },
        };

        Ok(GetTransactionReceiptResult {
            transaction_hash,
            events,
            finality_status,
            execution_status,
        })
    }

    async fn get_chain_id(&self) -> Result<HexBytes32, ChainHandlerError> {
        self.starknet_provider
            .chain_id()
            .await
            .map(|chain_id| chain_id.into())
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))
    }

    async fn get_latest_block_number(&self) -> Result<u64, ChainHandlerError> {
        self.starknet_provider
            .block_number()
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))
    }

    async fn is_valid_signature(
        &self,
        account_address: HexBytes32,
        signature: Vec<HexBytes32>,
        message_hash: HexBytes32,
    ) -> Result<bool, ChainHandlerError> {
        let is_signature_valid = self
            .starknet_provider
            .call(
                FunctionCall {
                    contract_address: account_address.to_felt()?,
                    entry_point_selector: IS_VALID_SIGNATURE_SELECTOR,
                    calldata: [
                        vec![message_hash.to_felt()?, signature.len().into()],
                        signature.to_felt()?,
                    ]
                    .concat(),
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;

        if is_signature_valid.len() > 1 {
            return Err(ChainHandlerError::InvalidReturnTypeForFunctionCall(
                "is_valid_signature return value is not a single felt".to_string(),
            ));
        }

        // VALID in hex is 0x56414c4944
        Ok(is_signature_valid[0] == Felt::from_hex_unchecked("0x56414c4944"))
    }

    async fn identity_contains_signer(
        &self,
        identity_address: HexBytes32,
        account_address: HexBytes32,
    ) -> Result<bool, ChainHandlerError> {
        let key_result = self
            .starknet_provider
            .call(
                FunctionCall {
                    contract_address: identity_address.to_felt()?,
                    entry_point_selector: GET_KEY_SELECTOR,
                    calldata: vec![account_address.to_felt()?],
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;

        if key_result.is_empty() {
            return Err(ChainHandlerError::InvalidReturnTypeForFunctionCall(
                "get_key return value is empty".to_string(),
            ));
        }

        // Check if the last element in the returned value matches the key itself
        // If the account_address is not the last element, then the identity is invalid
        // Safe to unwrap because we already checked that the result is not empty
        let last_result = key_result.last().unwrap();
        if *last_result != account_address.to_felt()? {
            return Ok(false);
        }
        Ok(true)
    }

    async fn get_transaction_by_hash(
        &self,
        transaction_hash: HexBytes32,
    ) -> Result<GetTransactionByHashResult, ChainHandlerError> {
        let transaction = self
            .starknet_provider
            .get_transaction_by_hash(transaction_hash.to_felt()?)
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;
        Ok(GetTransactionByHashResult {
            sender_address: transaction
                .get_sender_address()
                .ok_or(ChainHandlerError::InvalidTransactionType)?
                .into(),
        })
    }

    async fn contract_has_function(
        &self,
        contract_address: HexBytes32,
        function_name: String,
    ) -> Result<bool, ChainHandlerError> {
        let has_selector = contract_address_has_selector(
            self.starknet_provider.clone(),
            contract_address.to_felt()?,
            BlockId::Tag(BlockTag::Pending),
            get_selector_from_name(function_name.as_str())
                .map_err(|e| ChainHandlerError::InvalidFunctionName(e.to_string()))?,
        )
        .await
        .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?;
        Ok(has_selector)
    }

    async fn simulate_read_access_check(
        &self,
        caller_address: HexBytes32,
        contract_address: HexBytes32,
        function_name: String,
        calldata: Vec<HexBytes32>,
    ) -> Result<bool, ChainHandlerError> {
        simulate_boolean_read(
            vec![Call {
                to: contract_address.to_felt()?,
                selector: get_selector_from_name(function_name.as_str())
                    .map_err(|e| ChainHandlerError::InvalidFunctionName(e.to_string()))?,
                calldata: calldata.to_felt()?,
            }],
            caller_address.to_felt()?,
            self.starknet_provider.clone(),
        )
        .await
        .map_err(|e| ChainHandlerError::SimulationError(e.to_string()))
    }

    async fn compute_class_hash(
        &self,
        program: &serde_json::Value,
    ) -> Result<HexBytes32, ChainHandlerError> {
        // TODO: Can we avoid cloning the program?
        let class: FlattenedSierraClass = serde_json::from_value(program.clone())
            .map_err(|e| ChainHandlerError::InvalidProgram(e.to_string()))?;
        let class_hash = class.class_hash();
        Ok(class_hash.into())
    }

    async fn set_class_visibility(
        &self,
        class_hash: HexBytes32,
        visibility: ClassVisibility,
        sender_address: HexBytes32,
    ) -> Result<HexBytes32, ChainHandlerError> {
        self.owner_wallet()
            .execute_v3(vec![Call {
                to: self.declare_acl_address(),
                selector: selector!("set_visibility"),
                calldata: vec![
                    class_hash.to_felt()?,
                    visibility.into(),
                    sender_address.to_felt()?,
                ],
            }])
            .gas(0)
            .gas_price(0)
            .send()
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?
            .wait_for_receipt(self.starknet_provider.clone(), None)
            .await
            .map_err(ChainHandlerError::from)?;
        Ok(class_hash)
    }

    async fn get_class_visibility(
        &self,
        class_hash: HexBytes32,
    ) -> Result<ClassVisibility, ChainHandlerError> {
        let visibility = self
            .starknet_provider
            .call(
                FunctionCall {
                    contract_address: self.declare_acl_address(),
                    entry_point_selector: selector!("get_visibility"),
                    calldata: vec![class_hash.to_felt()?],
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await
            .map_err(|e| ChainHandlerError::ProviderError(e.to_string()))?
            .try_into()
            .map_err(|e: ClassVisibilityError| {
                ChainHandlerError::InvalidReturnTypeForFunctionCall(e.to_string())
            })?;

        Ok(visibility)
    }

    fn get_declare_acl_address(&self) -> HexBytes32 {
        self.declare_acl_address().into()
    }
}
