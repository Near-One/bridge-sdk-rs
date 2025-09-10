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
pub enum Chain {
    BitcoinMainnet,
    BitcoinTestnet,
    LitecoinMainnet,
    LitecoinTestnet,
    ZcashMainnet,
    ZcashTestnet,
    DogecoinMainnet,
    DogecoinTestnet,
}

impl Chain {
    pub fn is_zcash(&self) -> bool {
        matches!(self, Self::ZcashMainnet | Self::ZcashTestnet)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    P2pkh {
        hash: PubkeyHash,
        chain: Chain,
    },
    P2sh {
        hash: ScriptHash,
        chain: Chain,
    },
    Segwit {
        program: WitnessProgram,
        chain: Chain,
    },
    Unified {
        address: zcash_address::unified::Address,
        chain: Chain,
    },
}

impl zcash_address::TryFromAddress for Address {
    type Error = &'static str;
    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        let chain = match net {
            NetworkType::Main => Chain::ZcashMainnet,
            NetworkType::Test => Chain::ZcashTestnet,
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
            NetworkType::Main => Chain::ZcashMainnet,
            NetworkType::Test => Chain::ZcashTestnet,
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

impl Address {
    /// Parse an address string + chain into `AddressInner`
    pub fn parse(address: &str, chain: Chain) -> Result<Self, String> {
        if chain == Chain::ZcashMainnet || chain == Chain::ZcashTestnet {
            let addr = ZcashAddress::try_from_encoded(address)
                .map_err(|e| format!("Error on parsing ZCash Address: {e}"))?;

            let network = match chain {
                Chain::ZcashMainnet => NetworkType::Main,
                Chain::ZcashTestnet => NetworkType::Test,
                _ => unreachable!(),
            };

            return Ok(addr.convert_if_network::<Self>(network)
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

                return Ok(Address::Segwit { program, chain });
            }
        }

        let data = bitcoin::base58::decode_check(address)
            .map_err(|e| format!("Base58 decode error: {e}"))?;

        let prefix = get_pubkey_address_prefix(chain);
        if data.starts_with(&prefix) {
            let hash = PubkeyHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid pubkey hash: {e}"))?;
            return Ok(Address::P2pkh { hash, chain });
        }

        let prefix = get_script_address_prefix(chain);
        if data.starts_with(&prefix) {
            let hash = ScriptHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid script hash: {e}"))?;
            return Ok(Address::P2sh { hash, chain });
        }

        Err("Unknown address format or unsupported chain".to_string())
    }

    /// Return the scriptPubKey corresponding to this address
    pub fn script_pubkey(&self) -> bitcoin::ScriptBuf {
        match self {
            Address::P2pkh { hash, .. } => bitcoin::ScriptBuf::new_p2pkh(hash),
            Address::P2sh { hash, .. } => bitcoin::ScriptBuf::new_p2sh(hash),
            Address::Segwit { program, .. } => bitcoin::ScriptBuf::new_witness_program(program),
            Address::Unified { address, .. } => {
                let receiver_list = address.items_as_parsed();
                for receiver in receiver_list {
                    match receiver {
                        Receiver::P2pkh(data) => {
                            return bitcoin::ScriptBuf::new_p2pkh(
                                &PubkeyHash::from_slice(&data[..]).unwrap(),
                            )
                        }
                        Receiver::P2sh(data) => {
                            return bitcoin::ScriptBuf::new_p2sh(
                                &ScriptHash::from_slice(&data[..]).unwrap(),
                            )
                        }
                        _ => {}
                    }
                }

                panic!("No receiver found in address")
            }
        }
    }

    pub fn from_pubkey(chain: Chain, pubkey: bitcoin::PublicKey) -> Self {
        let pubkey_hash = pubkey.pubkey_hash();

        if let Some(_hrp) = get_segwit_hrp(&chain) {
            // Chain supports Bech32 SegWit
            let wp = WitnessProgram::p2wpkh(&pubkey.try_into().unwrap());
            Address::Segwit { program: wp, chain }
        } else {
            // Legacy P2PKH
            Address::P2pkh {
                hash: pubkey_hash,
                chain,
            }
        }
    }

    pub fn from_script(script: &bitcoin::Script, chain: Chain) -> Option<Self> {
        // Try P2PKH
        if script.is_p2pkh() {
            let hash = bitcoin::PubkeyHash::from_slice(&script.as_bytes()[3..23]).ok()?;
            return Some(Address::P2pkh { hash, chain });
        }

        // Try P2SH
        if script.is_p2sh() {
            let hash = bitcoin::ScriptHash::from_slice(&script.as_bytes()[2..22]).ok()?;
            return Some(Address::P2sh { hash, chain });
        }

        if script.is_witness_program() {
            let opcode = script
                .first_opcode()
                .expect("is_witness_program guarantees len > 4");

            let version = WitnessVersion::try_from(opcode).ok()?;
            let program = WitnessProgram::new(version, &script.as_bytes()[2..]).ok()?;
            return Some(Address::Segwit { program, chain });
        }

        None
    }
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use Address::{P2pkh, P2sh, Segwit, Unified};
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
                    Chain::ZcashMainnet => NetworkType::Main,
                    Chain::ZcashTestnet => NetworkType::Test,
                    _ => unreachable!(),
                };

                let str_address = ZcashAddress::from_unified(network, address.clone()).encode();
                write!(fmt, "{str_address}")
            }
        }
    }
}

pub fn get_segwit_hrp(chain: &Chain) -> Option<&'static str> {
    #[allow(clippy::match_same_arms)]
    match chain {
        // Bitcoin (Bech32 - BIP173)
        Chain::BitcoinMainnet => Some("bc"),
        Chain::BitcoinTestnet => Some("tb"),

        // Litecoin (Bech32)
        Chain::LitecoinMainnet => Some("ltc"),
        Chain::LitecoinTestnet => Some("tltc"),

        // Zcash (Bech32m) support unified addresses with hrp but not segwit
        Chain::ZcashMainnet | Chain::ZcashTestnet => None,

        // Dogecoin (no native Bech32 support yet)
        Chain::DogecoinMainnet | Chain::DogecoinTestnet => None,
    }
}

/// Returns the P2PKH (pubkey) address prefix as a Vec<u8>
fn get_pubkey_address_prefix(chain: Chain) -> Vec<u8> {
    #[allow(clippy::match_same_arms)]
    match chain {
        // Bitcoin
        Chain::BitcoinMainnet => vec![0x00], // "1"
        Chain::BitcoinTestnet => vec![0x6F], // "m" or "n"

        // Litecoin
        Chain::LitecoinMainnet => vec![0x30], // "L"
        Chain::LitecoinTestnet => vec![0x6F],

        // Zcash
        Chain::ZcashMainnet => vec![0x1C, 0xB8], // "t1"
        Chain::ZcashTestnet => vec![0x1D, 0x25], // "tm"

        // Dogecoin
        Chain::DogecoinMainnet => vec![0x1E], // "D"
        Chain::DogecoinTestnet => vec![0x71], // "n"
    }
}

/// Returns the P2SH (script) address prefix as a Vec<u8>
fn get_script_address_prefix(chain: Chain) -> Vec<u8> {
    #[allow(clippy::match_same_arms)]
    match chain {
        // Bitcoin
        Chain::BitcoinMainnet => vec![0x05], // "3"
        Chain::BitcoinTestnet => vec![0xC4], // "2"

        // Litecoin
        Chain::LitecoinMainnet => vec![0x32], // "M" (was "3")
        Chain::LitecoinTestnet => vec![0x3A],

        // Zcash
        Chain::ZcashMainnet => vec![0x1C, 0xBD], // "t3"
        Chain::ZcashTestnet => vec![0x1C, 0xBA], // "t2"

        // Dogecoin
        Chain::DogecoinMainnet => vec![0x16], // "9"
        Chain::DogecoinTestnet => vec![0xC4], // same as Bitcoin testnet
    }
}
