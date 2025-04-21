use starknet_crypto::Felt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassVisibility {
    Acl,
    Public,
}

// TODO: Move behind a feature flag?
#[derive(Debug, thiserror::Error)]
pub enum ClassVisibilityError {
    #[error("Invalid class visibility")]
    InvalidClassVisibility,
}

impl TryFrom<Vec<Felt>> for ClassVisibility {
    type Error = ClassVisibilityError;

    fn try_from(value: Vec<Felt>) -> Result<Self, Self::Error> {
        if value.len() != 1 {
            return Err(ClassVisibilityError::InvalidClassVisibility);
        }
        let visibility = value[0];
        if visibility == Felt::ZERO {
            Ok(ClassVisibility::Acl)
        } else if visibility == Felt::ONE {
            Ok(ClassVisibility::Public)
        } else {
            Err(ClassVisibilityError::InvalidClassVisibility)
        }
    }
}

impl From<ClassVisibility> for Felt {
    fn from(value: ClassVisibility) -> Self {
        match value {
            ClassVisibility::Acl => Felt::ZERO,
            ClassVisibility::Public => Felt::ONE,
        }
    }
}
