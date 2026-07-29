//! Per-token patching of the vendored `token_template` bytecode.
//!
//! Sui cannot create a currency at runtime (`coin::create_currency` needs a
//! one-time witness), so every NEAR-originated token gets its own copy of the
//! tiny `token_template` package with the module/OTW identifiers, the
//! `decimals` constant, and the `[symbol, name, description]` params constant
//! substituted. There is no Move compiler on crates.io, so instead of
//! compiling per token we patch the precompiled module at the binary-format
//! table level:
//!
//! ```text
//! magic(4) | version(u32 LE, flavor in MSB) | table_count(uleb)
//! table headers: (kind: u8, offset: uleb, len: uleb) * count
//! table contents (offsets relative to contents start)
//! trailer (self module handle index) — preserved verbatim
//! ```
//!
//! Only the IDENTIFIERS (0x7) and CONSTANT_POOL (0x6) tables are rewritten;
//! every other table is treated as an opaque blob and re-emitted with a
//! recomputed offset. Entries are located by their sentinel values from
//! `token_template/sources/template_coin.move`, so the patcher is
//! order-independent. The identity patch is byte-lossless (see tests), and
//! patched output is validated against the real toolchain via
//! `sui move disassemble` (see `tests/fixtures/usdt_coin_patched.mv`).

use crate::error::{Result, SuiBridgeClientError};

/// Compiled `token_template::template_coin`, built with `sui move build`
/// (bytecode v7, Sui flavor). See `token_template/` for source & provenance.
pub const TOKEN_TEMPLATE_BYTECODE: &[u8] = include_bytes!("template/template_coin.mv");

/// Addresses of the packages the template links against: MoveStdlib (0x1)
/// and the Sui framework (0x2), as reported by `sui move build`.
pub const TOKEN_TEMPLATE_DEPENDENCIES: [[u8; 32]; 2] = [
    {
        let mut a = [0u8; 32];
        a[31] = 1;
        a
    },
    {
        let mut a = [0u8; 32];
        a[31] = 2;
        a
    },
];

const MOVE_MAGIC: [u8; 4] = [0xA1, 0x1C, 0xEB, 0x0B];
const TABLE_IDENTIFIERS: u8 = 0x7;
const TABLE_CONSTANT_POOL: u8 = 0x6;

// Sentinels as compiled from the template source. Symbol/name/description
// live in ONE `vector<vector<u8>>` constant (`PARAMS`): the Move verifier
// rejects modules with duplicate constant-pool entries, so separate
// `vector<u8>` constants would make publishing fail whenever
// `symbol == name` or either equals the empty description. The combined
// constant and the `u8` decimals constant have different types, so no token
// metadata can ever produce a duplicate.
const TEMPLATE_MODULE_NAME: &str = "template_coin";
const TEMPLATE_OTW_NAME: &str = "TEMPLATE_COIN";
const TEMPLATE_DECIMALS: u8 = 9;
const TEMPLATE_SYMBOL: &[u8] = b"TMPL";
const TEMPLATE_NAME: &[u8] = b"Template Token";
const TEMPLATE_DESCRIPTION: &[u8] = b"";

/// Sui protocol `max_move_identifier_len` is 128; stay comfortably below
/// after the `_coin` suffix.
const MAX_SANITIZED_SYMBOL_LEN: usize = 64;

fn err(msg: impl Into<String>) -> SuiBridgeClientError {
    SuiBridgeClientError::BytecodeError(msg.into())
}

fn read_uleb(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| err("unexpected end of bytecode in uleb128"))?;
        *pos += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 {
            return Err(err("uleb128 overflow in bytecode"));
        }
    }
}

fn write_uleb(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

struct ParsedModule {
    /// magic + version, verbatim.
    header: Vec<u8>,
    /// (kind, contents) in original directory order.
    tables: Vec<(u8, Vec<u8>)>,
    /// Bytes after the table contents (self module handle index), verbatim.
    trailer: Vec<u8>,
}

fn parse_module(data: &[u8]) -> Result<ParsedModule> {
    if data.len() < 8 || data[..4] != MOVE_MAGIC {
        return Err(err("template bytecode has invalid magic"));
    }
    let mut pos = 8;
    let table_count = read_uleb(data, &mut pos)?;
    let mut headers = Vec::new();
    for _ in 0..table_count {
        let kind = *data
            .get(pos)
            .ok_or_else(|| err("unexpected end of bytecode in table header"))?;
        pos += 1;
        let offset = read_uleb(data, &mut pos)?;
        let len = read_uleb(data, &mut pos)?;
        headers.push((kind, offset as usize, len as usize));
    }
    let contents_start = pos;
    let contents_len = headers
        .iter()
        .map(|&(_, offset, len)| offset + len)
        .max()
        .unwrap_or(0);
    let mut tables = Vec::with_capacity(headers.len());
    for (kind, offset, len) in headers {
        let start = contents_start + offset;
        let end = start + len;
        if end > data.len() {
            return Err(err("table extends past end of bytecode"));
        }
        tables.push((kind, data[start..end].to_vec()));
    }
    let trailer_start = contents_start + contents_len;
    if trailer_start > data.len() {
        return Err(err("table contents extend past end of bytecode"));
    }
    Ok(ParsedModule {
        header: data[..8].to_vec(),
        tables,
        trailer: data[trailer_start..].to_vec(),
    })
}

fn serialize_module(module: &ParsedModule) -> Vec<u8> {
    let mut out = module.header.clone();
    write_uleb(&mut out, module.tables.len() as u64);
    let mut offset = 0usize;
    for (kind, contents) in &module.tables {
        out.push(*kind);
        write_uleb(&mut out, offset as u64);
        write_uleb(&mut out, contents.len() as u64);
        offset += contents.len();
    }
    for (_, contents) in &module.tables {
        out.extend_from_slice(contents);
    }
    out.extend_from_slice(&module.trailer);
    out
}

/// IDENTIFIERS table: `(uleb len, utf8 bytes) * n`.
fn parse_identifiers(blob: &[u8]) -> Result<Vec<String>> {
    let mut identifiers = Vec::new();
    let mut pos = 0;
    while pos < blob.len() {
        let len = read_uleb(blob, &mut pos)? as usize;
        let end = pos + len;
        if end > blob.len() {
            return Err(err("identifier extends past end of table"));
        }
        let ident = std::str::from_utf8(&blob[pos..end])
            .map_err(|_| err("identifier is not valid UTF-8"))?;
        identifiers.push(ident.to_string());
        pos = end;
    }
    Ok(identifiers)
}

fn serialize_identifiers(identifiers: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for ident in identifiers {
        write_uleb(&mut out, ident.len() as u64);
        out.extend_from_slice(ident.as_bytes());
    }
    out
}

#[derive(PartialEq)]
enum ConstantType {
    U8,
    /// `vector<vector<u8>>` — the combined `[symbol, name, description]`
    /// params constant.
    VectorVectorU8,
}

/// CONSTANT_POOL table: `(signature token(s), uleb data len, data) * n`.
/// The template only contains `u8` (0x02) and `vector<vector<u8>>`
/// (0x0A 0x0A 0x02) constants; anything else fails loudly so a template
/// change can't be silently mis-patched.
fn parse_constants(blob: &[u8]) -> Result<Vec<(ConstantType, Vec<u8>)>> {
    let mut constants = Vec::new();
    let mut pos = 0;
    while pos < blob.len() {
        let ty = match blob.get(pos) {
            Some(0x02) => {
                pos += 1;
                ConstantType::U8
            }
            Some(0x0A) if blob.get(pos + 1) == Some(&0x0A) && blob.get(pos + 2) == Some(&0x02) => {
                pos += 3;
                ConstantType::VectorVectorU8
            }
            Some(token) => {
                return Err(err(format!("unsupported constant type token {token:#04x}")))
            }
            None => return Err(err("unexpected end of constant pool")),
        };
        let len = read_uleb(blob, &mut pos)? as usize;
        let end = pos + len;
        if end > blob.len() {
            return Err(err("constant extends past end of table"));
        }
        constants.push((ty, blob[pos..end].to_vec()));
        pos = end;
    }
    Ok(constants)
}

fn serialize_constants(constants: &[(ConstantType, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (ty, data) in constants {
        match ty {
            ConstantType::U8 => out.push(0x02),
            ConstantType::VectorVectorU8 => out.extend_from_slice(&[0x0A, 0x0A, 0x02]),
        }
        write_uleb(&mut out, data.len() as u64);
        out.extend_from_slice(data);
    }
    out
}

/// A `vector<u8>` element inside a BCS `vector<vector<u8>>`: uleb length +
/// bytes.
fn bcs_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_uleb(&mut out, bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

/// The BCS data of the `PARAMS: vector<vector<u8>>` constant:
/// `[symbol, name, description]`.
fn params_data(symbol: &[u8], name: &[u8], description: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_uleb(&mut out, 3);
    out.extend_from_slice(&bcs_bytes(symbol));
    out.extend_from_slice(&bcs_bytes(name));
    out.extend_from_slice(&bcs_bytes(description));
    out
}

/// Derives the per-token module and OTW identifiers from the token symbol,
/// e.g. `"USDT"` -> `("usdt_coin", "USDT_COIN")`. Mirrors the naming rule in
/// the canonical template's docs (module = symbol, struct = module in ALL
/// CAPS); the `_coin` suffix keeps the identifier valid (non-empty, not a
/// keyword, no leading digit) for any symbol.
pub fn coin_module_identifiers(symbol: &str) -> (String, String) {
    let mut module: String = symbol
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .map(|c| c.to_ascii_lowercase())
        .take(MAX_SANITIZED_SYMBOL_LEN)
        .collect();
    module = module.trim_matches('_').to_string();
    let module = if module.is_empty() || module.starts_with(|c: char| c.is_ascii_digit()) {
        format!("bridge_{module}_coin").replace("__", "_")
    } else {
        format!("{module}_coin")
    };
    let otw = module.to_ascii_uppercase();
    (module, otw)
}

/// Patches `template` (the compiled `template_coin` module) into a per-token
/// module: renames the module/OTW identifiers and substitutes the
/// `decimals` and `[symbol, name, description]` constants. Both constant
/// sentinels and both identifier sentinels must be found, otherwise the
/// vendored template and this patcher have drifted apart and the call fails.
pub fn patch_token_template(
    template: &[u8],
    module_name: &str,
    otw_name: &str,
    symbol: &str,
    name: &str,
    decimals: u8,
) -> Result<Vec<u8>> {
    let mut module = parse_module(template)?;

    let mut renamed_module = false;
    let mut renamed_otw = false;
    let mut patched_decimals = false;
    let mut patched_params = false;
    let template_params = params_data(TEMPLATE_SYMBOL, TEMPLATE_NAME, TEMPLATE_DESCRIPTION);

    for (kind, contents) in &mut module.tables {
        match *kind {
            TABLE_IDENTIFIERS => {
                let mut identifiers = parse_identifiers(contents)?;
                for ident in &mut identifiers {
                    if ident == TEMPLATE_MODULE_NAME {
                        *ident = module_name.to_string();
                        renamed_module = true;
                    } else if ident == TEMPLATE_OTW_NAME {
                        *ident = otw_name.to_string();
                        renamed_otw = true;
                    }
                }
                *contents = serialize_identifiers(&identifiers);
            }
            TABLE_CONSTANT_POOL => {
                let mut constants = parse_constants(contents)?;
                for (ty, data) in &mut constants {
                    if *ty == ConstantType::U8 && data.as_slice() == [TEMPLATE_DECIMALS] {
                        *data = vec![decimals];
                        patched_decimals = true;
                    } else if *ty == ConstantType::VectorVectorU8 && *data == template_params {
                        *data =
                            params_data(symbol.as_bytes(), name.as_bytes(), TEMPLATE_DESCRIPTION);
                        patched_params = true;
                    }
                }
                // The Move verifier rejects duplicate constant-pool entries.
                // Impossible with the combined params constant, but guard
                // against template drift reintroducing separate constants.
                for (i, a) in constants.iter().enumerate() {
                    if constants[..i].iter().any(|b| a == b) {
                        return Err(err("patched constant pool contains duplicate entries — \
                             the Move verifier would reject this module"));
                    }
                }
                *contents = serialize_constants(&constants);
            }
            _ => {}
        }
    }

    if !(renamed_module && renamed_otw && patched_decimals && patched_params) {
        return Err(err(
            "template sentinels not found — vendored bytecode and patcher have drifted",
        ));
    }
    Ok(serialize_module(&module))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Validated against the real toolchain: `sui move disassemble` on this
    /// fixture shows `module 0.usdt_coin`, `struct USDT_COIN`, and constants
    /// `u8: 6` / `vector<vector<u8>>: ["USDT", "Tether USD", ""]`.
    const USDT_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/usdt_coin_patched.mv"
    ));

    #[test]
    fn identity_patch_is_byte_lossless() {
        let patched = patch_token_template(
            TOKEN_TEMPLATE_BYTECODE,
            TEMPLATE_MODULE_NAME,
            TEMPLATE_OTW_NAME,
            "TMPL",
            "Template Token",
            TEMPLATE_DECIMALS,
        )
        .unwrap();
        assert_eq!(patched, TOKEN_TEMPLATE_BYTECODE);
    }

    #[test]
    fn usdt_patch_matches_toolchain_validated_fixture() {
        let patched = patch_token_template(
            TOKEN_TEMPLATE_BYTECODE,
            "usdt_coin",
            "USDT_COIN",
            "USDT",
            "Tether USD",
            6,
        )
        .unwrap();
        assert_eq!(patched, USDT_FIXTURE);
    }

    /// Patch, parse back, and assert the expected identifiers/constants —
    /// including that the pool has no duplicates (the Move verifier would
    /// reject the module otherwise).
    fn patch_and_verify(module_name: &str, otw_name: &str, symbol: &str, name: &str, decimals: u8) {
        let patched = patch_token_template(
            TOKEN_TEMPLATE_BYTECODE,
            module_name,
            otw_name,
            symbol,
            name,
            decimals,
        )
        .unwrap();
        let module = parse_module(&patched).unwrap();
        let identifiers = module
            .tables
            .iter()
            .find(|(kind, _)| *kind == TABLE_IDENTIFIERS)
            .map(|(_, contents)| parse_identifiers(contents).unwrap())
            .unwrap();
        assert!(identifiers.iter().any(|i| i == module_name));
        assert!(identifiers.iter().any(|i| i == otw_name));
        assert!(!identifiers.iter().any(|i| i == TEMPLATE_MODULE_NAME));
        let constants = module
            .tables
            .iter()
            .find(|(kind, _)| *kind == TABLE_CONSTANT_POOL)
            .map(|(_, contents)| parse_constants(contents).unwrap())
            .unwrap();
        assert!(constants
            .iter()
            .any(|(ty, data)| *ty == ConstantType::U8 && data.as_slice() == [decimals]));
        assert!(constants.iter().any(|(ty, data)| {
            *ty == ConstantType::VectorVectorU8
                && *data == params_data(symbol.as_bytes(), name.as_bytes(), TEMPLATE_DESCRIPTION)
        }));
        for (i, a) in constants.iter().enumerate() {
            assert!(
                !constants[..i].iter().any(|b| a == b),
                "duplicate constant-pool entry — the Move verifier rejects this"
            );
        }
    }

    #[test]
    fn patched_module_parses_back_with_expected_values() {
        patch_and_verify(
            "wbtc_coin",
            "WBTC_COIN",
            "WBTC",
            "Wrapped Bitcoin (bridged)",
            8,
        );
    }

    #[test]
    fn symbol_equal_to_name_produces_no_duplicate_constants() {
        // Common with memecoins / wrapped assets: identical symbol and name.
        patch_and_verify("pepe_coin", "PEPE_COIN", "PEPE", "PEPE", 8);
    }

    #[test]
    fn empty_symbol_produces_no_duplicate_constants() {
        // An empty symbol/name must not collide with the empty description.
        patch_and_verify("bridge_coin", "BRIDGE_COIN", "", "Wrapped Foo", 6);
    }

    #[test]
    fn empty_name_produces_no_duplicate_constants() {
        patch_and_verify("foo_coin", "FOO_COIN", "FOO", "", 6);
    }

    #[test]
    fn all_empty_metadata_produces_no_duplicate_constants() {
        patch_and_verify("bridge_coin", "BRIDGE_COIN", "", "", 0);
    }

    #[test]
    fn long_metadata_uses_multibyte_uleb_lengths() {
        // A >127-byte name makes both the inner element length and the outer
        // constant data length multi-byte ULEBs.
        let long_name = "N".repeat(200);
        patch_and_verify("long_coin", "LONG_COIN", "LONG", &long_name, 9);
    }

    #[test]
    fn sanitizes_symbols_into_valid_identifiers() {
        assert_eq!(
            coin_module_identifiers("USDT"),
            ("usdt_coin".to_string(), "USDT_COIN".to_string())
        );
        assert_eq!(
            coin_module_identifiers("WBTC.e"),
            ("wbtce_coin".to_string(), "WBTCE_COIN".to_string())
        );
        assert_eq!(
            coin_module_identifiers("1INCH"),
            (
                "bridge_1inch_coin".to_string(),
                "BRIDGE_1INCH_COIN".to_string()
            )
        );
        assert_eq!(
            coin_module_identifiers(""),
            ("bridge_coin".to_string(), "BRIDGE_COIN".to_string())
        );
        assert_eq!(
            coin_module_identifiers("_"),
            ("bridge_coin".to_string(), "BRIDGE_COIN".to_string())
        );
    }
}
