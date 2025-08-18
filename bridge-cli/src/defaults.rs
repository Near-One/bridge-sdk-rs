/// Mainnet
pub const NEAR_RPC_MAINNET: &str = "https://archival-rpc.mainnet.fastnear.com/";
pub const NEAR_TOKEN_LOCKER_ID_MAINNET: &str = "omni.bridge.near";
pub const ETH_LIGHT_CLIENT_ID_MAINNET: &str = "client-eth2.bridge.near";

pub const ETH_RPC_MAINNET: &str = "https://eth.llamarpc.com";
pub const ETH_CHAIN_ID_MAINNET: u64 = 1;
pub const ETH_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET: &str =
    "0xe00c629aFaCCb0510995A2B95560E446A24c85B9";

pub const BASE_RPC_MAINNET: &str = "https://base.llamarpc.com";
pub const BASE_CHAIN_ID_MAINNET: u64 = 8453;
pub const BASE_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET: &str =
    "0xd025b38762B4A4E36F0Cde483b86CB13ea00D989";
pub const BASE_WORMHOLE_ADDRESS_MAINNET: &str = "0xbebdb6C8ddC678FfA9f8748f85C815C556Dd8ac6";

pub const ARB_RPC_MAINNET: &str = "https://arbitrum.llamarpc.com";
pub const ARB_CHAIN_ID_MAINNET: u64 = 42_161;
pub const ARB_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET: &str =
    "0xd025b38762B4A4E36F0Cde483b86CB13ea00D989";
pub const ARB_WORMHOLE_ADDRESS_MAINNET: &str = "0xa5f208e072434bC67592E4C49C1B991BA79BCA46";

pub const BNB_RPC_MAINNET: &str = "https://bsc-rpc.publicnode.com";
pub const BNB_CHAIN_ID_MAINNET: u64 = 56;
pub const BNB_BRIDGE_TOKEN_FACTORY_ADDRESS_MAINNET: &str =
    "0x073C8a225c8Cf9d3f9157F5C1a1DbE02407f5720";
pub const BNB_WORMHOLE_ADDRESS_MAINNET: &str = "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B";

pub const SOLANA_RPC_MAINNET: &str = "https://api.mainnet-beta.solana.com";
pub const SOLANA_BRIDGE_ADDRESS_MAINNET: &str = "dahPEoZGXfyV58JqqH85okdHmpN8U2q8owgPUXSCPxe";
pub const SOLANA_WORMHOLE_ADDRESS_MAINNET: &str = "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth";

pub const WORMHOLE_API_MAINNET: &str = "https://api.wormholescan.io";
pub const BTC_ENDPOINT_MAINNET: &str = "https://bitcoin-rpc.publicnode.com";
pub const BTC_CONNECTOR_MAINNET: &str = "btc-connector.bridge.near";
pub const BTC_MAINNET: &str = "btc-client.bridge.near";
pub const SATOSHI_RELAYER_MAINNET: &str = "satoshi_optwo.near";

pub const ZCASH_ENDPOINT_MAINNET: &str = "";
pub const ZCASH_CONNECTOR_MAINNET: &str = "";
pub const ZCASH_MAINNET: &str = "";

/// Testnet
pub const NEAR_RPC_TESTNET: &str = "https://archival-rpc.testnet.fastnear.com/";
pub const NEAR_TOKEN_LOCKER_ID_TESTNET: &str = "omni.n-bridge.testnet";
pub const ETH_LIGHT_CLIENT_ID_TESTNET: &str = "client-eth2.sepolia.testnet";

pub const ETH_RPC_TESTNET: &str = "https://ethereum-sepolia-rpc.publicnode.com";
pub const ETH_CHAIN_ID_TESTNET: u64 = 11_155_111;
pub const ETH_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET: &str =
    "0x68a86e0Ea5B1d39F385c1326e4d493526dFe4401";

pub const BASE_RPC_TESTNET: &str = "https://base-sepolia-rpc.publicnode.com";
pub const BASE_CHAIN_ID_TESTNET: u64 = 84_532;
pub const BASE_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET: &str =
    "0xa56b860017152cD296ad723E8409Abd6e5D86d4d";
pub const BASE_WORMHOLE_ADDRESS_TESTNET: &str = "0x79A1027a6A159502049F10906D333EC57E95F083";

pub const ARB_RPC_TESTNET: &str = "https://arbitrum-sepolia-rpc.publicnode.com";
pub const ARB_CHAIN_ID_TESTNET: u64 = 421_614;
pub const ARB_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET: &str =
    "0x0C981337fFe39a555d3A40dbb32f21aD0eF33FFA";
pub const ARB_WORMHOLE_ADDRESS_TESTNET: &str = "0x6b9C8671cdDC8dEab9c719bB87cBd3e782bA6a35";

pub const BNB_RPC_TESTNET: &str = "https://bsc-testnet-rpc.publicnode.com";
pub const BNB_CHAIN_ID_TESTNET: u64 = 97;
pub const BNB_BRIDGE_TOKEN_FACTORY_ADDRESS_TESTNET: &str =
    "0xEC81aFc3485a425347Ac03316675e58a680b283A";
pub const BNB_WORMHOLE_ADDRESS_TESTNET: &str = "0x68605AD7b15c732a30b1BbC62BE8F2A509D74b4D";

pub const SOLANA_RPC_TESTNET: &str = "https://api.devnet.solana.com";
pub const SOLANA_BRIDGE_ADDRESS_TESTNET: &str = "862HdJV59Vp83PbcubUnvuXc4EAXP8CDDs6LTxFpunTe";
pub const SOLANA_WORMHOLE_ADDRESS_TESTNET: &str = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";

pub const WORMHOLE_API_TESTNET: &str = "https://api.testnet.wormholescan.io";
pub const BTC_ENDPOINT_TESTNET: &str = "https://bitcoin-testnet-rpc.publicnode.com";
pub const BTC_CONNECTOR_TESTNET: &str = "brg-dev.testnet";
pub const BTC_TESTNET: &str = "nbtc-dev.testnet";
pub const SATOSHI_RELAYER_TESTNET: &str = "cosmosfirst.testnet";

pub const ZCASH_ENDPOINT_TESTNET: &str = "https://zcash-testnet.gateway.tatum.io/";
pub const ZCASH_CONNECTOR_TESTNET: &str = "zcash_connector.n-bridge.testnet";
pub const ZCASH_TESTNET: &str = "nzcash.n-bridge.testnet";

/// Devnet
pub const NEAR_RPC_DEVNET: &str = "https://archival-rpc.testnet.near.org/";
pub const NEAR_TOKEN_LOCKER_ID_DEVNET: &str = "omni-locker.testnet";
pub const ETH_LIGHT_CLIENT_ID_DEVNET: &str = "client-eth2.sepolia.testnet";

pub const ETH_RPC_DEVNET: &str = "https://ethereum-sepolia-rpc.publicnode.com";
pub const ETH_CHAIN_ID_DEVNET: u64 = 11_155_111;
pub const ETH_BRIDGE_TOKEN_FACTORY_ADDRESS_DEVNET: &str =
    "0x3701B9859Dbb9a4333A3dd933ab18e9011ddf2C8";

pub const BASE_RPC_DEVNET: &str = "https://base-sepolia-rpc.publicnode.com";
pub const BASE_CHAIN_ID_DEVNET: u64 = 84_532;
pub const BASE_BRIDGE_TOKEN_FACTORY_ADDRESS_DEVNET: &str =
    "0x0C981337fFe39a555d3A40dbb32f21aD0eF33FFA";
pub const BASE_WORMHOLE_ADDRESS_DEVNET: &str = "0x79A1027a6A159502049F10906D333EC57E95F083";

pub const ARB_RPC_DEVNET: &str = "https://arbitrum-sepolia-rpc.publicnode.com";
pub const ARB_CHAIN_ID_DEVNET: u64 = 421_614;
pub const ARB_BRIDGE_TOKEN_FACTORY_ADDRESS_DEVNET: &str =
    "0xd025b38762B4A4E36F0Cde483b86CB13ea00D989";
pub const ARB_WORMHOLE_ADDRESS_DEVNET: &str = "0x6b9C8671cdDC8dEab9c719bB87cBd3e782bA6a35";

pub const BNB_RPC_DEVNET: &str = "https://bsc-testnet-rpc.publicnode.com";
pub const BNB_CHAIN_ID_DEVNET: u64 = 97;
pub const BNB_BRIDGE_TOKEN_FACTORY_ADDRESS_DEVNET: &str =
    "0xEC81aFc3485a425347Ac03316675e58a680b283A";
pub const BNB_WORMHOLE_ADDRESS_DEVNET: &str = "0x68605AD7b15c732a30b1BbC62BE8F2A509D74b4D";

pub const SOLANA_RPC_DEVNET: &str = "https://api.devnet.solana.com";
pub const SOLANA_BRIDGE_ADDRESS_DEVNET: &str = "Gy1XPwYZURfBzHiGAxnw3SYC33SfqsEpGSS5zeBge28p";
pub const SOLANA_WORMHOLE_ADDRESS_DEVNET: &str = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";

pub const WORMHOLE_API_DEVNET: &str = "https://api.testnet.wormholescan.io";
pub const BTC_ENDPOINT_DEVNET: &str = "https://bitcoin-testnet-rpc.publicnode.com";
pub const BTC_CONNECTOR_DEVNET: &str = "brg-dev.testnet";
pub const BTC_DEVNET: &str = "nbtc-dev.testnet";
pub const SATOSHI_RELAYER_DEVNET: &str = "cosmosfirst.testnet";

pub const ZCASH_ENDPOINT_DEVNET: &str = "https://zcash-testnet.gateway.tatum.io/";
pub const ZCASH_CONNECTOR_DEVNET: &str = "zcash_connector.n-bridge.testnet";
pub const ZCASH_DEVNET: &str = "nzcash.n-bridge.testnet";
