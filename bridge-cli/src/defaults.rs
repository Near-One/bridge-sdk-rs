//! Per-network defaults. Each module defines the same set of constants, so
//! `config::network_defaults!` can build a `CliConfig` from any of them.
//! Adding a chain means adding its constants to all three modules.

pub mod mainnet {
    pub const NEAR_RPC: &str = "https://archival-rpc.mainnet.fastnear.com/";
    pub const NEAR_TOKEN_LOCKER_ID: &str = "omni.bridge.near";
    pub const NEAR_MPC_OMNI_PROVER_ID: &str = "mpc-prover.bridge.near";
    pub const BRIDGE_INDEXER_API: &str = "https://mainnet.api.bridge.nearone.org";
    pub const ETH_LIGHT_CLIENT_ID: &str = "client-eth2.bridge.near";
    pub const BTC_LIGHT_CLIENT_ID: &str = "btc-client.bridge.near";
    pub const ZCASH_LIGHT_CLIENT_ID: &str = "zcash-client.bridge.near";

    pub const ETH_RPC: &str = "https://ethereum-rpc.publicnode.com";
    pub const ETH_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0xe00c629aFaCCb0510995A2B95560E446A24c85B9";

    pub const BASE_RPC: &str = "https://base-rpc.publicnode.com";
    pub const BASE_BRIDGE_TOKEN_FACTORY_ADDRESS: &str =
        "0xd025b38762B4A4E36F0Cde483b86CB13ea00D989";
    pub const BASE_WORMHOLE_ADDRESS: &str = "0xbebdb6C8ddC678FfA9f8748f85C815C556Dd8ac6";

    pub const ARB_RPC: &str = "https://arbitrum-one-rpc.publicnode.com";
    pub const ARB_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0xd025b38762B4A4E36F0Cde483b86CB13ea00D989";
    pub const ARB_WORMHOLE_ADDRESS: &str = "0xa5f208e072434bC67592E4C49C1B991BA79BCA46";

    pub const BNB_RPC: &str = "https://bsc-rpc.publicnode.com";
    pub const BNB_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0x073C8a225c8Cf9d3f9157F5C1a1DbE02407f5720";
    pub const BNB_WORMHOLE_ADDRESS: &str = "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B";

    pub const POL_RPC: &str = "https://polygon-bor-rpc.publicnode.com";
    pub const POL_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0xd025b38762B4A4E36F0Cde483b86CB13ea00D989";
    pub const POL_WORMHOLE_ADDRESS: &str = "0x7A4B5a56256163F07b2C80A7cA55aBE66c4ec4d7";

    pub const HYPEREVM_RPC: &str = "https://rpc.hyperliquid.xyz/evm";
    pub const HYPEREVM_BRIDGE_TOKEN_FACTORY_ADDRESS: &str =
        "0xf353b40fC144d1c6c5BCdda712fa6De833016aF9";
    pub const HYPEREVM_WORMHOLE_ADDRESS: &str = "0x7C0faFc4384551f063e05aee704ab943b8B53aB3";

    pub const HYPERCORE_API: &str = "https://api.hyperliquid.xyz";
    // Match the Hyperliquid Python SDK convention (signing.py:250) which uses
    // 0x66eee (Arb-Sepolia) for the EIP-712 domain on both mainnet and testnet.
    // The signatureChainId only needs to be unique across chains to prevent
    // signature replay; both 0xa4b1 (Arbitrum) and 0x66eee work, but mirroring
    // the canonical SDK reduces interop surprises.
    pub const HYPERCORE_SIGNATURE_CHAIN_ID: &str = "0x66eee";

    pub const ABS_RPC: &str = "https://api.mainnet.abs.xyz";
    pub const ABS_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0xd2490A00bDB97C1EDE4fdf207CFE2664AFB9C20D";

    pub const SOLANA_RPC: &str = "https://api.mainnet-beta.solana.com";
    pub const SOLANA_BRIDGE_ADDRESS: &str = "dahPEoZGXfyV58JqqH85okdHmpN8U2q8owgPUXSCPxe";
    pub const SOLANA_WORMHOLE_ADDRESS: &str = "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth";
    pub const SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID: &str =
        "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX";

    pub const WORMHOLE_API: &str = "https://api.wormholescan.io";

    pub const BTC_ENDPOINT: &str = "https://bitcoin-rpc.publicnode.com";
    pub const BTC_CONNECTOR: &str = "btc-connector.bridge.near";
    pub const BTC_TOKEN: &str = "nbtc.bridge.near";
    pub const SATOSHI_RELAYER: &str = "satoshi_optwo.near";

    pub const ZCASH_ENDPOINT: &str = "https://zcash-mainnet.gateway.tatum.io/";
    pub const ZCASH_CONNECTOR: &str = "zcash-connector.bridge.near";
    pub const ZCASH_TOKEN: &str = "nzec.bridge.near";
    pub const ENABLE_ORCHARD_BUNDLE: bool = false;

    pub const STARKNET_RPC: &str = "https://starknet-rpc.publicnode.com";
    pub const STARKNET_BRIDGE_ADDRESS: &str =
        "0x05f9a4a841dfb7bb3cde33073b2450fe45dcd407fb6c0985a274b0e943ad8598";
    pub const STARKNET_CHAIN_ID: &str = "SN_MAIN";

    pub const APTOS_RPC: &str = "https://fullnode.mainnet.aptoslabs.com/v1";
    pub const APTOS_BRIDGE_ADDRESS: &str =
        "0xe4ec15f237e5a8c7daa7a34ece28e2bd2c079360763f181bf65862ec148b914a";

    pub const FOGO_RPC: &str = "https://mainnet.fogo.io";
    pub const FOGO_BRIDGE_ADDRESS: Option<&str> =
        Some("dahPEoZGXfyV58JqqH85okdHmpN8U2q8owgPUXSCPxe");
    pub const FOGO_WORMHOLE_ADDRESS: &str = "worm2mrQkG1B1KTz37erMfWN8anHkSK24nzca7UD8BB";
    pub const FOGO_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID: &str =
        SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID;
}

pub mod testnet {
    pub const NEAR_RPC: &str = "https://archival-rpc.testnet.fastnear.com/";
    pub const NEAR_TOKEN_LOCKER_ID: &str = "omni.n-bridge.testnet";
    pub const NEAR_MPC_OMNI_PROVER_ID: &str = "mpc-prover.n-bridge.testnet";
    pub const BRIDGE_INDEXER_API: &str = "https://testnet.api.bridge.nearone.org";
    pub const ETH_LIGHT_CLIENT_ID: &str = "client-eth2.sepolia.testnet";
    pub const BTC_LIGHT_CLIENT_ID: &str = "btc-client-v4.testnet";
    pub const ZCASH_LIGHT_CLIENT_ID: &str = "zcash-client.n-bridge.testnet";

    pub const ETH_RPC: &str = "https://ethereum-sepolia-rpc.publicnode.com";
    pub const ETH_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0x68a86e0Ea5B1d39F385c1326e4d493526dFe4401";

    pub const BASE_RPC: &str = "https://base-sepolia-rpc.publicnode.com";
    pub const BASE_BRIDGE_TOKEN_FACTORY_ADDRESS: &str =
        "0xa56b860017152cD296ad723E8409Abd6e5D86d4d";
    pub const BASE_WORMHOLE_ADDRESS: &str = "0x79A1027a6A159502049F10906D333EC57E95F083";

    pub const ARB_RPC: &str = "https://arbitrum-sepolia-rpc.publicnode.com";
    pub const ARB_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0x0C981337fFe39a555d3A40dbb32f21aD0eF33FFA";
    pub const ARB_WORMHOLE_ADDRESS: &str = "0x6b9C8671cdDC8dEab9c719bB87cBd3e782bA6a35";

    pub const BNB_RPC: &str = "https://bsc-testnet-rpc.publicnode.com";
    pub const BNB_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0xEC81aFc3485a425347Ac03316675e58a680b283A";
    pub const BNB_WORMHOLE_ADDRESS: &str = "0x68605AD7b15c732a30b1BbC62BE8F2A509D74b4D";

    pub const POL_RPC: &str = "https://polygon-amoy-bor-rpc.publicnode.com";
    pub const POL_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0xEC81aFc3485a425347Ac03316675e58a680b283A";
    pub const POL_WORMHOLE_ADDRESS: &str = "0x6b9C8671cdDC8dEab9c719bB87cBd3e782bA6a35";

    pub const HYPEREVM_RPC: &str = "https://rpc.hyperliquid-testnet.xyz/evm";
    pub const HYPEREVM_BRIDGE_TOKEN_FACTORY_ADDRESS: &str =
        "0xf353b40fC144d1c6c5BCdda712fa6De833016aF9";
    pub const HYPEREVM_WORMHOLE_ADDRESS: &str = "0xBB73cB66C26740F31d1FabDC6b7A46a038A300dd";

    pub const HYPERCORE_API: &str = "https://api.hyperliquid-testnet.xyz";
    pub const HYPERCORE_SIGNATURE_CHAIN_ID: &str = "0x66eee";

    pub const ABS_RPC: &str = "https://api.testnet.abs.xyz";
    pub const ABS_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0x5C79627d2cD753d45B41839d187619f99c7B8D78";

    pub const SOLANA_RPC: &str = "https://api.devnet.solana.com";
    pub const SOLANA_BRIDGE_ADDRESS: &str = "862HdJV59Vp83PbcubUnvuXc4EAXP8CDDs6LTxFpunTe";
    pub const SOLANA_WORMHOLE_ADDRESS: &str = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";
    pub const SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID: &str =
        "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX";

    pub const WORMHOLE_API: &str = "https://api.testnet.wormholescan.io";

    pub const BTC_ENDPOINT: &str = "https://bitcoin-testnet-rpc.publicnode.com";
    pub const BTC_CONNECTOR: &str = "btc-connector.n-bridge.testnet";
    pub const BTC_TOKEN: &str = "nbtc.n-bridge.testnet";
    pub const SATOSHI_RELAYER: &str = "cosmosfirst.testnet";

    pub const ZCASH_ENDPOINT: &str = "https://zcash-testnet.gateway.tatum.io/";
    pub const ZCASH_CONNECTOR: &str = "zcash_connector.n-bridge.testnet";
    pub const ZCASH_TOKEN: &str = "nzcash.n-bridge.testnet";
    pub const ENABLE_ORCHARD_BUNDLE: bool = true;

    pub const STARKNET_RPC: &str = "https://starknet-sepolia-rpc.publicnode.com";
    pub const STARKNET_BRIDGE_ADDRESS: &str =
        "0x02830785fd87b181c5391819f4a5e6a0b2d76c49d92b7f748a2433495eead162";
    pub const STARKNET_CHAIN_ID: &str = "SN_SEPOLIA";

    pub const APTOS_RPC: &str = "https://fullnode.testnet.aptoslabs.com/v1";
    pub const APTOS_BRIDGE_ADDRESS: &str =
        "0x904a7d620944eec42d5d46cf4fe12463f713c8a705d581c10a010672228f967c";

    pub const FOGO_RPC: &str = "https://testnet.fogo.io";
    pub const FOGO_BRIDGE_ADDRESS: Option<&str> = None;
    pub const FOGO_WORMHOLE_ADDRESS: &str = "BhnQyKoQQgpuRTRo6D8Emz93PvXCYfVgHhnrR4T3qhw4";
    pub const FOGO_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID: &str =
        SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID;
}

pub mod devnet {
    use super::testnet;

    pub const NEAR_RPC: &str = "https://archival-rpc.testnet.near.org/";
    pub const NEAR_TOKEN_LOCKER_ID: &str = "omni-locker.testnet";
    pub const NEAR_MPC_OMNI_PROVER_ID: &str = testnet::NEAR_MPC_OMNI_PROVER_ID;
    pub const BRIDGE_INDEXER_API: &str = testnet::BRIDGE_INDEXER_API;
    pub const ETH_LIGHT_CLIENT_ID: &str = testnet::ETH_LIGHT_CLIENT_ID;
    pub const BTC_LIGHT_CLIENT_ID: &str = testnet::BTC_LIGHT_CLIENT_ID;
    pub const ZCASH_LIGHT_CLIENT_ID: &str = testnet::ZCASH_LIGHT_CLIENT_ID;

    pub const ETH_RPC: &str = testnet::ETH_RPC;
    pub const ETH_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0x3701B9859Dbb9a4333A3dd933ab18e9011ddf2C8";

    pub const BASE_RPC: &str = testnet::BASE_RPC;
    pub const BASE_BRIDGE_TOKEN_FACTORY_ADDRESS: &str =
        "0x0C981337fFe39a555d3A40dbb32f21aD0eF33FFA";
    pub const BASE_WORMHOLE_ADDRESS: &str = testnet::BASE_WORMHOLE_ADDRESS;

    pub const ARB_RPC: &str = testnet::ARB_RPC;
    pub const ARB_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0xd025b38762B4A4E36F0Cde483b86CB13ea00D989";
    pub const ARB_WORMHOLE_ADDRESS: &str = testnet::ARB_WORMHOLE_ADDRESS;

    pub const BNB_RPC: &str = testnet::BNB_RPC;
    pub const BNB_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = testnet::BNB_BRIDGE_TOKEN_FACTORY_ADDRESS;
    pub const BNB_WORMHOLE_ADDRESS: &str = testnet::BNB_WORMHOLE_ADDRESS;

    pub const POL_RPC: &str = testnet::POL_RPC;
    pub const POL_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = testnet::POL_BRIDGE_TOKEN_FACTORY_ADDRESS;
    pub const POL_WORMHOLE_ADDRESS: &str = testnet::POL_WORMHOLE_ADDRESS;

    pub const HYPEREVM_RPC: &str = testnet::HYPEREVM_RPC;
    pub const HYPEREVM_BRIDGE_TOKEN_FACTORY_ADDRESS: &str =
        testnet::HYPEREVM_BRIDGE_TOKEN_FACTORY_ADDRESS;
    pub const HYPEREVM_WORMHOLE_ADDRESS: &str = testnet::HYPEREVM_WORMHOLE_ADDRESS;

    pub const HYPERCORE_API: &str = testnet::HYPERCORE_API;
    pub const HYPERCORE_SIGNATURE_CHAIN_ID: &str = testnet::HYPERCORE_SIGNATURE_CHAIN_ID;

    pub const ABS_RPC: &str = testnet::ABS_RPC;
    pub const ABS_BRIDGE_TOKEN_FACTORY_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

    pub const SOLANA_RPC: &str = testnet::SOLANA_RPC;
    pub const SOLANA_BRIDGE_ADDRESS: &str = "Gy1XPwYZURfBzHiGAxnw3SYC33SfqsEpGSS5zeBge28p";
    pub const SOLANA_WORMHOLE_ADDRESS: &str = testnet::SOLANA_WORMHOLE_ADDRESS;
    pub const SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID: &str =
        testnet::SOLANA_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID;

    pub const WORMHOLE_API: &str = testnet::WORMHOLE_API;

    pub const BTC_ENDPOINT: &str = testnet::BTC_ENDPOINT;
    pub const BTC_CONNECTOR: &str = testnet::BTC_CONNECTOR;
    pub const BTC_TOKEN: &str = testnet::BTC_TOKEN;
    pub const SATOSHI_RELAYER: &str = testnet::SATOSHI_RELAYER;

    pub const ZCASH_ENDPOINT: &str = testnet::ZCASH_ENDPOINT;
    pub const ZCASH_CONNECTOR: &str = testnet::ZCASH_CONNECTOR;
    pub const ZCASH_TOKEN: &str = testnet::ZCASH_TOKEN;
    pub const ENABLE_ORCHARD_BUNDLE: bool = true;

    pub const STARKNET_RPC: &str = testnet::STARKNET_RPC;
    pub const STARKNET_BRIDGE_ADDRESS: &str =
        "0x05a0ad01b18eba34432d22e4cb5c987560cae87a785b494ed58d9553a98bdc8f";
    pub const STARKNET_CHAIN_ID: &str = testnet::STARKNET_CHAIN_ID;

    pub const APTOS_RPC: &str = testnet::APTOS_RPC;
    pub const APTOS_BRIDGE_ADDRESS: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    pub const FOGO_RPC: &str = testnet::FOGO_RPC;
    pub const FOGO_BRIDGE_ADDRESS: Option<&str> = None;
    pub const FOGO_WORMHOLE_ADDRESS: &str = testnet::FOGO_WORMHOLE_ADDRESS;
    pub const FOGO_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID: &str =
        testnet::FOGO_WORMHOLE_POST_MESSAGE_SHIM_PROGRAM_ID;
}
