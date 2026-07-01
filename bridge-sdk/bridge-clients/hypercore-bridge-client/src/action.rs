use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HyperliquidNetwork {
    Mainnet,
    Testnet,
}

impl HyperliquidNetwork {
    /// `hyperliquidChain` value embedded in the signed action JSON.
    #[must_use]
    pub fn hyperliquid_chain(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
        }
    }

    /// HyperEVM chain id (`destinationChainId` in the action JSON).
    #[must_use]
    pub fn hyperevm_chain_id(self) -> u32 {
        match self {
            Self::Mainnet => 999,
            Self::Testnet => 998,
        }
    }
}

/// JSON body of a `sendToEvmWithData` Hyperliquid Core action.
///
/// Field order matches the inferred EIP-712 type list; reordering will change the
/// type hash and invalidate signatures.
#[derive(Debug, Clone, Serialize)]
pub struct SendToEvmWithDataAction {
    #[serde(rename = "type")]
    pub action_type: &'static str,
    #[serde(rename = "hyperliquidChain")]
    pub hyperliquid_chain: &'static str,
    #[serde(rename = "signatureChainId")]
    pub signature_chain_id: String,
    pub token: String,
    pub amount: String,
    #[serde(rename = "sourceDex")]
    pub source_dex: String,
    #[serde(rename = "destinationRecipient")]
    pub destination_recipient: String,
    #[serde(rename = "addressEncoding")]
    pub address_encoding: String,
    #[serde(rename = "destinationChainId")]
    pub destination_chain_id: u32,
    #[serde(rename = "gasLimit")]
    pub gas_limit: u64,
    pub data: String,
    pub nonce: u64,
}

/// Format an integer amount + decimals as a minimal Hyperliquid decimal string
/// (no trailing zeros, no leading zeros except a single `0` before the decimal point).
#[must_use]
pub fn format_amount(amount: u128, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let raw = amount.to_string();
    let dec = decimals as usize;
    if raw.len() <= dec {
        let mut frac = "0".repeat(dec - raw.len());
        frac.push_str(&raw);
        let trimmed = frac.trim_end_matches('0');
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            format!("0.{trimmed}")
        }
    } else {
        let split = raw.len() - dec;
        let int = &raw[..split];
        let frac = raw[split..].trim_end_matches('0');
        if frac.is_empty() {
            int.to_string()
        } else {
            format!("{int}.{frac}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_amount_examples() {
        assert_eq!(format_amount(0, 8), "0");
        assert_eq!(format_amount(1, 8), "0.00000001");
        assert_eq!(format_amount(100_000_000, 8), "1");
        assert_eq!(format_amount(123_456_789, 8), "1.23456789");
        assert_eq!(format_amount(100_000_000_000, 8), "1000");
        assert_eq!(format_amount(10, 0), "10");
        assert_eq!(format_amount(1_000, 2), "10");
        assert_eq!(format_amount(123, 2), "1.23");
        assert_eq!(format_amount(120, 2), "1.2");
    }
}
