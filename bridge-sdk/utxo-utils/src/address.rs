use bitcoin::bech32::Hrp;
use bitcoin::hashes::Hash;
use bitcoin::{base58, bech32, PubkeyHash, ScriptHash, WitnessProgram, WitnessVersion};
use near_sdk::near;
use std::fmt;
use zcash_address;
use zcash_address::unified::{Container, Receiver};
use zcash_address::{ConversionError, ToAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

#[near(serializers = [borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UTXOChain {
    BitcoinMainnet,
    BitcoinTestnet,
    LitecoinMainnet,
    LitecoinTestnet,
    ZcashMainnet,
    ZcashTestnet,
    DogecoinMainnet,
    DogecoinTestnet,
}

impl UTXOChain {
    pub fn is_zcash(&self) -> bool {
        matches!(self, Self::ZcashMainnet | Self::ZcashTestnet)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UTXOAddress {
    P2pkh {
        hash: PubkeyHash,
        chain: UTXOChain,
    },
    P2sh {
        hash: ScriptHash,
        chain: UTXOChain,
    },
    Segwit {
        program: WitnessProgram,
        chain: UTXOChain,
    },
    Unified {
        address: zcash_address::unified::Address,
        chain: UTXOChain,
    },
}

impl zcash_address::TryFromAddress for UTXOAddress {
    type Error = &'static str;
    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        let chain = match net {
            NetworkType::Main => UTXOChain::ZcashMainnet,
            NetworkType::Test => UTXOChain::ZcashTestnet,
            NetworkType::Regtest => {
                return Err("Regtest network not supported".into());
            }
        };

        Ok(Self::P2pkh {
            hash: PubkeyHash::from_slice(&data[..])
                .map_err(|_e| "Invalid pubkey hash for Zcash address")?,
            chain,
        })
    }

    fn try_from_unified(
        net: NetworkType,
        data: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let chain = match net {
            NetworkType::Main => UTXOChain::ZcashMainnet,
            NetworkType::Test => UTXOChain::ZcashTestnet,
            NetworkType::Regtest => {
                return Err("Regtest network not supported".into());
            }
        };

        Ok(Self::Unified {
            address: data,
            chain,
        })
    }
}

impl UTXOAddress {
    /// Parse an address string + chain into `AddressInner`
    pub fn parse(address: &str, chain: UTXOChain) -> Result<Self, String> {
        if chain == UTXOChain::ZcashMainnet || chain == UTXOChain::ZcashTestnet {
            let addr = ZcashAddress::try_from_encoded(address)
                .map_err(|e| format!("Error on parsing ZCash Address: {e}"))?;

            let network = match chain {
                UTXOChain::ZcashMainnet => NetworkType::Main,
                UTXOChain::ZcashTestnet => NetworkType::Test,
                _ => unreachable!(),
            };

            return Ok(addr
                .convert_if_network::<Self>(network)
                .map_err(|_e| "Failed to convert Zcash address network")?);
        }

        if let Some(hrp) = get_segwit_hrp(&chain) {
            if let Ok((decoded_hrp, witness_version, data)) = bech32::segwit::decode(address) {
                if decoded_hrp.as_str() != hrp {
                    return Err(format!(
                        "Bech32 HRP mismatch: expected '{hrp}', got '{decoded_hrp}'"
                    ));
                }

                let version =
                    WitnessVersion::try_from(witness_version).map_err(|err| format!("{err:?}"))?;
                let program = WitnessProgram::new(version, &data)
                    .expect("bech32 guarantees valid program length for witness");

                return Ok(UTXOAddress::Segwit { program, chain });
            }
        }

        let data = bitcoin::base58::decode_check(address)
            .map_err(|e| format!("Base58 decode error: {e}"))?;

        let prefix = get_pubkey_address_prefix(chain);
        if data.starts_with(&prefix) {
            let hash = PubkeyHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid pubkey hash: {e}"))?;
            return Ok(UTXOAddress::P2pkh { hash, chain });
        }

        let prefix = get_script_address_prefix(chain);
        if data.starts_with(&prefix) {
            let hash = ScriptHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid script hash: {e}"))?;
            return Ok(UTXOAddress::P2sh { hash, chain });
        }

        Err("Unknown address format or unsupported chain".to_string())
    }

    /// Return the scriptPubKey corresponding to this address
    pub fn script_pubkey(&self) -> Result<bitcoin::ScriptBuf, String> {
        match self {
            UTXOAddress::P2pkh { hash, .. } => Ok(bitcoin::ScriptBuf::new_p2pkh(hash)),
            UTXOAddress::P2sh { hash, .. } => Ok(bitcoin::ScriptBuf::new_p2sh(hash)),
            UTXOAddress::Segwit { program, .. } => {
                Ok(bitcoin::ScriptBuf::new_witness_program(program))
            }
            UTXOAddress::Unified { address, .. } => {
                let receiver_list = address.items_as_parsed();
                for receiver in receiver_list {
                    match receiver {
                        Receiver::P2pkh(data) => {
                            return Ok(bitcoin::ScriptBuf::new_p2pkh(
                                &PubkeyHash::from_slice(&data[..])
                                    .map_err(|e| format!("Failed to create pubkey hash: {e}"))?,
                            ));
                        }
                        Receiver::P2sh(data) => {
                            return Ok(bitcoin::ScriptBuf::new_p2sh(
                                &ScriptHash::from_slice(&data[..])
                                    .map_err(|e| format!("Failed to create script hash: {e}"))?,
                            ));
                        }
                        _ => {}
                    }
                }

                Err("No receiver found in address".to_string())
            }
        }
    }

    pub fn from_pubkey(chain: UTXOChain, pubkey: bitcoin::PublicKey) -> Result<Self, String> {
        let pubkey_hash = pubkey.pubkey_hash();

        if let Some(_hrp) = get_segwit_hrp(&chain) {
            // Chain supports Bech32 SegWit
            let wp = WitnessProgram::p2wpkh(
                &pubkey
                    .try_into()
                    .map_err(|e| format!("Failed to convert pubkey: {e}"))?,
            );
            Ok(UTXOAddress::Segwit { program: wp, chain })
        } else {
            // Legacy P2PKH
            Ok(UTXOAddress::P2pkh {
                hash: pubkey_hash,
                chain,
            })
        }
    }

    pub fn from_script(script: &bitcoin::Script, chain: UTXOChain) -> Option<Self> {
        // Try P2PKH
        if script.is_p2pkh() {
            let hash = bitcoin::PubkeyHash::from_slice(&script.as_bytes()[3..23]).ok()?;
            return Some(UTXOAddress::P2pkh { hash, chain });
        }

        // Try P2SH
        if script.is_p2sh() {
            let hash = bitcoin::ScriptHash::from_slice(&script.as_bytes()[2..22]).ok()?;
            return Some(UTXOAddress::P2sh { hash, chain });
        }

        if script.is_witness_program() {
            let opcode = script
                .first_opcode()
                .expect("is_witness_program guarantees len > 4");

            let version = WitnessVersion::try_from(opcode).ok()?;
            let program = WitnessProgram::new(version, &script.as_bytes()[2..]).ok()?;
            return Some(UTXOAddress::Segwit { program, chain });
        }

        None
    }
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for UTXOAddress {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use UTXOAddress::{P2pkh, P2sh, Segwit, Unified};
        match self {
            P2pkh { hash, chain } => {
                let prefix = get_pubkey_address_prefix(*chain);
                let mut prefixed = Vec::with_capacity(20 + prefix.len());
                prefixed.extend(prefix);
                prefixed.extend(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh { hash, chain } => {
                let prefix = get_script_address_prefix(*chain);
                let mut prefixed = Vec::with_capacity(20 + prefix.len());
                prefixed.extend(prefix);
                prefixed.extend(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Segwit { program, chain } => {
                let hrp = Hrp::parse(get_segwit_hrp(chain).expect("Unsupported chain"))
                    .expect("Invalid HRP");
                let version = program.version().to_fe();
                let program = program.program().as_ref();

                if fmt.alternate() {
                    bech32::segwit::encode_upper_to_fmt_unchecked(fmt, hrp, version, program)
                } else {
                    bech32::segwit::encode_lower_to_fmt_unchecked(fmt, hrp, version, program)
                }
            }
            Unified { address, chain } => {
                let network = match chain {
                    UTXOChain::ZcashMainnet => NetworkType::Main,
                    UTXOChain::ZcashTestnet => NetworkType::Test,
                    _ => unreachable!(),
                };

                let str_address = ZcashAddress::from_unified(network, address.clone()).encode();
                write!(fmt, "{str_address}")
            }
        }
    }
}

pub fn get_segwit_hrp(chain: &UTXOChain) -> Option<&'static str> {
    #[allow(clippy::match_same_arms)]
    match chain {
        // Bitcoin (Bech32 - BIP173)
        UTXOChain::BitcoinMainnet => Some("bc"),
        UTXOChain::BitcoinTestnet => Some("tb"),

        // Litecoin (Bech32)
        UTXOChain::LitecoinMainnet => Some("ltc"),
        UTXOChain::LitecoinTestnet => Some("tltc"),

        // Zcash (Bech32m) support unified addresses with hrp but not segwit
        UTXOChain::ZcashMainnet | UTXOChain::ZcashTestnet => None,

        // Dogecoin (no native Bech32 support yet)
        UTXOChain::DogecoinMainnet | UTXOChain::DogecoinTestnet => None,
    }
}

/// Returns the P2PKH (pubkey) address prefix as a Vec<u8>
fn get_pubkey_address_prefix(chain: UTXOChain) -> Vec<u8> {
    #[allow(clippy::match_same_arms)]
    match chain {
        // Bitcoin
        UTXOChain::BitcoinMainnet => vec![0x00], // "1"
        UTXOChain::BitcoinTestnet => vec![0x6F], // "m" or "n"

        // Litecoin
        UTXOChain::LitecoinMainnet => vec![0x30], // "L"
        UTXOChain::LitecoinTestnet => vec![0x6F],

        // Zcash
        UTXOChain::ZcashMainnet => vec![0x1C, 0xB8], // "t1"
        UTXOChain::ZcashTestnet => vec![0x1D, 0x25], // "tm"

        // Dogecoin
        UTXOChain::DogecoinMainnet => vec![0x1E], // "D"
        UTXOChain::DogecoinTestnet => vec![0x71], // "n"
    }
}

/// Returns the P2SH (script) address prefix as a Vec<u8>
fn get_script_address_prefix(chain: UTXOChain) -> Vec<u8> {
    #[allow(clippy::match_same_arms)]
    match chain {
        // Bitcoin
        UTXOChain::BitcoinMainnet => vec![0x05], // "3"
        UTXOChain::BitcoinTestnet => vec![0xC4], // "2"

        // Litecoin
        UTXOChain::LitecoinMainnet => vec![0x32], // "M" (was "3")
        UTXOChain::LitecoinTestnet => vec![0x3A],

        // Zcash
        UTXOChain::ZcashMainnet => vec![0x1C, 0xBD], // "t3"
        UTXOChain::ZcashTestnet => vec![0x1C, 0xBA], // "t2"

        // Dogecoin
        UTXOChain::DogecoinMainnet => vec![0x16], // "9"
        UTXOChain::DogecoinTestnet => vec![0xC4], // same as Bitcoin testnet
    }
}
