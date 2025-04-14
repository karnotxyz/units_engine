#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclareTransactionResult {
    pub class_hash: String,
    pub transaction_hash: Option<String>,
    pub acl_updated: bool,
}
