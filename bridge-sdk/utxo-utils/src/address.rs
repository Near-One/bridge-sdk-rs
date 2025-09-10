use bitcoin::bech32::Hrp;
use bitcoin::hashes::Hash;
use bitcoin::{base58, bech32, PubkeyHash, ScriptHash, WitnessProgram, WitnessVersion};
use omni_types::ChainKind;
use std::fmt;
use zcash_address;
use zcash_address::unified::{Container, Receiver};
use zcash_address::{ConversionError, ToAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl From<Network> for NetworkType {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => NetworkType::Main,
            Network::Testnet => NetworkType::Test,
        }
    }
}

impl TryFrom<NetworkType> for Network {
    type Error = &'static str;
    fn try_from(value: NetworkType) -> Result<Self, Self::Error> {
        match value {
            NetworkType::Main => Ok(Network::Mainnet),
            NetworkType::Test => Ok(Network::Testnet),
            NetworkType::Regtest => Err("Regtest network not supported"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UTXOAddress {
    P2pkh {
        hash: PubkeyHash,
        chain: ChainKind,
        network: Network,
    },
    P2sh {
        hash: ScriptHash,
        chain: ChainKind,
        network: Network,
    },
    Segwit {
        program: WitnessProgram,
        chain: ChainKind,
        network: Network,
    },
    Unified {
        address: zcash_address::unified::Address,
        chain: ChainKind,
        network: Network,
    },
}

impl zcash_address::TryFromAddress for UTXOAddress {
    type Error = &'static str;
    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        let (chain, network) = match net {
            NetworkType::Main => (ChainKind::Zcash, Network::Mainnet),
            NetworkType::Test => (ChainKind::Zcash, Network::Testnet),
            NetworkType::Regtest => {
                return Err("Regtest network not supported".into());
            }
        };

        Ok(Self::P2pkh {
            hash: PubkeyHash::from_slice(&data[..])
                .map_err(|_e| "Invalid pubkey hash for Zcash address")?,
            chain,
            network,
        })
    }

    fn try_from_unified(
        net: NetworkType,
        data: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let (chain, network) = match net {
            NetworkType::Main => (ChainKind::Zcash, Network::Mainnet),
            NetworkType::Test => (ChainKind::Zcash, Network::Testnet),
            NetworkType::Regtest => {
                return Err("Regtest network not supported".into());
            }
        };

        Ok(Self::Unified {
            address: data,
            chain,
            network,
        })
    }
}

impl UTXOAddress {
    /// Parse an address string + chain into `AddressInner`
    pub fn parse(address: &str, chain: ChainKind, network: Network) -> Result<Self, String> {
        if chain == ChainKind::Zcash {
            let addr = ZcashAddress::try_from_encoded(address)
                .map_err(|e| format!("Error on parsing ZCash Address: {e}"))?;

            return Ok(addr
                .convert_if_network::<Self>(network.into())
                .map_err(|_e| "Failed to convert Zcash address network")?);
        }

        if let Some(hrp) = get_segwit_hrp(chain, network) {
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

                return Ok(UTXOAddress::Segwit {
                    program,
                    chain,
                    network,
                });
            }
        }

        let data = bitcoin::base58::decode_check(address)
            .map_err(|e| format!("Base58 decode error: {e}"))?;

        let prefix = get_pubkey_address_prefix(chain, network);
        if data.starts_with(&prefix) {
            let hash = PubkeyHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid pubkey hash: {e}"))?;
            return Ok(UTXOAddress::P2pkh {
                hash,
                chain,
                network,
            });
        }

        let prefix = get_script_address_prefix(chain, network);
        if data.starts_with(&prefix) {
            let hash = ScriptHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid script hash: {e}"))?;
            return Ok(UTXOAddress::P2sh {
                hash,
                chain,
                network,
            });
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

    pub fn from_pubkey(
        chain: ChainKind,
        network: Network,
        pubkey: bitcoin::PublicKey,
    ) -> Result<Self, String> {
        let pubkey_hash = pubkey.pubkey_hash();

        if let Some(_hrp) = get_segwit_hrp(chain, network) {
            // Chain supports Bech32 SegWit
            let wp = WitnessProgram::p2wpkh(
                &pubkey
                    .try_into()
                    .map_err(|e| format!("Failed to convert pubkey: {e}"))?,
            );
            Ok(UTXOAddress::Segwit {
                program: wp,
                chain,
                network,
            })
        } else {
            // Legacy P2PKH
            Ok(UTXOAddress::P2pkh {
                hash: pubkey_hash,
                chain,
                network,
            })
        }
    }

    pub fn from_script(
        script: &bitcoin::Script,
        chain: ChainKind,
        network: Network,
    ) -> Option<Self> {
        // Try P2PKH
        if script.is_p2pkh() {
            let hash = bitcoin::PubkeyHash::from_slice(&script.as_bytes()[3..23]).ok()?;
            return Some(UTXOAddress::P2pkh {
                hash,
                chain,
                network,
            });
        }

        // Try P2SH
        if script.is_p2sh() {
            let hash = bitcoin::ScriptHash::from_slice(&script.as_bytes()[2..22]).ok()?;
            return Some(UTXOAddress::P2sh {
                hash,
                chain,
                network,
            });
        }

        if script.is_witness_program() {
            let opcode = script
                .first_opcode()
                .expect("is_witness_program guarantees len > 4");

            let version = WitnessVersion::try_from(opcode).ok()?;
            let program = WitnessProgram::new(version, &script.as_bytes()[2..]).ok()?;
            return Some(UTXOAddress::Segwit {
                program,
                chain,
                network,
            });
        }

        None
    }
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for UTXOAddress {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use UTXOAddress::{P2pkh, P2sh, Segwit, Unified};
        match self {
            P2pkh {
                hash,
                chain,
                network,
            } => {
                let prefix = get_pubkey_address_prefix(*chain, *network);
                let mut prefixed = Vec::with_capacity(20 + prefix.len());
                prefixed.extend(prefix);
                prefixed.extend(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh {
                hash,
                chain,
                network,
            } => {
                let prefix = get_script_address_prefix(*chain, *network);
                let mut prefixed = Vec::with_capacity(20 + prefix.len());
                prefixed.extend(prefix);
                prefixed.extend(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Segwit {
                program,
                chain,
                network,
            } => {
                let hrp = Hrp::parse(get_segwit_hrp(*chain, *network).expect("Unsupported chain"))
                    .expect("Invalid HRP");
                let version = program.version().to_fe();
                let program = program.program().as_ref();

                if fmt.alternate() {
                    bech32::segwit::encode_upper_to_fmt_unchecked(fmt, hrp, version, program)
                } else {
                    bech32::segwit::encode_lower_to_fmt_unchecked(fmt, hrp, version, program)
                }
            }
            Unified {
                address, network, ..
            } => {
                let str_address =
                    ZcashAddress::from_unified((*network).into(), address.clone()).encode();
                write!(fmt, "{str_address}")
            }
        }
    }
}

pub fn get_segwit_hrp(chain: ChainKind, network: Network) -> Option<&'static str> {
    #[allow(clippy::match_same_arms)]
    match (chain, network) {
        // Bitcoin (Bech32 - BIP173)
        (ChainKind::Btc, Network::Mainnet) => Some("bc"),
        (ChainKind::Btc, Network::Testnet) => Some("tb"),

        // TODO: Uncomment when Litecoin support is added
        // Litecoin (Bech32)
        // (ChainKind::Ltc, Network::Mainnet) => Some("ltc"),
        // (ChainKind::Ltc, Network::Testnet) => Some("tltc"),

        // Zcash (Bech32m) support unified addresses with hrp but not segwit
        (ChainKind::Zcash, _) => None,

        // TODO: Uncomment when Dogecoin support is added
        // Dogecoin (no native Bech32 support yet)
        // (ChainKind::Doge, _) => None,
        _ => unimplemented!("Unsupported chain or network"),
    }
}

/// Returns the P2PKH (pubkey) address prefix as a Vec<u8>
fn get_pubkey_address_prefix(chain: ChainKind, network: Network) -> Vec<u8> {
    #[allow(clippy::match_same_arms)]
    match (chain, network) {
        // Bitcoin
        (ChainKind::Btc, Network::Mainnet) => vec![0x00], // "1"
        (ChainKind::Btc, Network::Testnet) => vec![0x6F], // "m" or "n"

        // TODO: Uncomment when Litecoin support is added
        // Litecoin
        // (ChainKind::Ltc, Network::Mainnet) => vec![0x30], // "L"
        // (ChainKind::Ltc, Network::Testnet) => vec![0x6F],

        // Zcash
        (ChainKind::Zcash, Network::Mainnet) => vec![0x1C, 0xB8], // "t1"
        (ChainKind::Zcash, Network::Testnet) => vec![0x1D, 0x25], // "tm"

        // TODO: Uncomment when Dogecoin support is added
        // Dogecoin
        // (ChainKind::Doge, Network::Mainnet) => vec![0x1E], // "D"
        // (ChainKind::Doge, Network::Testnet) => vec![0x71], // "n"
        _ => unimplemented!("Unsupported chain or network"),
    }
}

/// Returns the P2SH (script) address prefix as a Vec<u8>
fn get_script_address_prefix(chain: ChainKind, network: Network) -> Vec<u8> {
    #[allow(clippy::match_same_arms)]
    match (chain, network) {
        // Bitcoin
        (ChainKind::Btc, Network::Mainnet) => vec![0x05], // "3"
        (ChainKind::Btc, Network::Testnet) => vec![0xC4], // "2"

        // TODO: Uncomment when Litecoin support is added
        // Litecoin
        // (ChainKind::Ltc, Network::Mainnet) => vec![0x32], // "M" (was "3")
        // (ChainKind::Ltc, Network::Testnet) => vec![0x3A],

        // Zcash
        (ChainKind::Zcash, Network::Mainnet) => vec![0x1C, 0xBD], // "t3"
        (ChainKind::Zcash, Network::Testnet) => vec![0x1C, 0xBA], // "t2"

        // TODO: Uncomment when Dogecoin support is added
        // Dogecoin
        // (ChainKind::Doge, Network::Mainnet) => vec![0x16], // "9"
        // (ChainKind::Doge, Network::Testnet) => vec![0xC4], // same as Bitcoin testnet
        _ => unimplemented!("Unsupported chain or network"),
    }
}
