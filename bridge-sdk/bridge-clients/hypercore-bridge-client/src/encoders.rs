use alloy::primitives::Address;
use alloy::sol_types::SolValue;
use omni_types::OmniAddress;

pub const ACTION_TRANSFER: u8 = 0x00;
pub const ACTION_INIT_TRANSFER: u8 = 0x01;

/// `data` payload for HlBridgeToken `ACTION_TRANSFER`:
/// release `amount` from the system-address pool to `recipient` on HyperEVM.
///
/// Layout: `0x00 || abi.encode(address recipient)`.
#[must_use]
pub fn encode_transfer_action(recipient: Address) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32);
    out.push(ACTION_TRANSFER);
    out.extend_from_slice(&recipient.abi_encode());
    out
}

/// `data` payload for HlBridgeToken `ACTION_INIT_TRANSFER`:
/// bridge `amount` via `OmniBridge.initTransfer` to `recipient` with `fee`.
///
/// Layout: `0x01 || abi.encode(uint128 fee, string recipient, string message)`.
#[must_use]
pub fn encode_init_transfer_action(fee: u128, recipient: &OmniAddress, message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 * 5);
    out.push(ACTION_INIT_TRANSFER);
    out.extend_from_slice(&(fee, recipient.to_string(), message.to_string()).abi_encode_params());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::sol_types::SolValue;

    #[test]
    fn transfer_action_round_trip() {
        let recipient = address!("00000000000000000000000000000000DeaDBeef");
        let encoded = encode_transfer_action(recipient);
        assert_eq!(encoded[0], ACTION_TRANSFER);
        let decoded = Address::abi_decode(&encoded[1..]).unwrap();
        assert_eq!(decoded, recipient);
    }

    #[test]
    fn init_transfer_action_round_trip() {
        let fee = 10u128;
        let recipient: OmniAddress = "near:alice.near".parse().unwrap();
        let message = "ref=hypercore";

        let encoded = encode_init_transfer_action(fee, &recipient, message);
        assert_eq!(encoded[0], ACTION_INIT_TRANSFER);

        let (decoded_fee, decoded_recipient, decoded_message) =
            <(u128, String, String)>::abi_decode_params(&encoded[1..]).unwrap();
        assert_eq!(decoded_fee, fee);
        assert_eq!(decoded_recipient, recipient.to_string());
        assert_eq!(decoded_message, message);
    }

    #[test]
    fn init_transfer_action_empty_message() {
        let fee = 0u128;
        let recipient: OmniAddress = "sol:11111111111111111111111111111111".parse().unwrap();
        let message = "";

        let encoded = encode_init_transfer_action(fee, &recipient, message);
        let (decoded_fee, decoded_recipient, decoded_message) =
            <(u128, String, String)>::abi_decode_params(&encoded[1..]).unwrap();
        assert_eq!(decoded_fee, fee);
        assert_eq!(decoded_recipient, recipient.to_string());
        assert_eq!(decoded_message, message);
    }
}
