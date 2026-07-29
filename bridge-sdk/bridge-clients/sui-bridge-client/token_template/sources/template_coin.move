/// SDK-local variant of the Omni Bridge Sui token template
/// (`omni-bridge/sui/token_template`), used by `sui-bridge-client` for the
/// automated `deploy_token` flow.
///
/// Differences from the canonical template are deliberate and cosmetic-only:
/// the per-token values are hoisted into named `const`s so they compile into
/// the module's constant pool, where `bytecode.rs` patches them. `symbol`,
/// `name`, and `description` live in a SINGLE `vector<vector<u8>>` constant
/// rather than three separate ones: the Move verifier rejects modules whose
/// constant pool contains duplicate entries, so separate constants would make
/// publishing fail for any token where `symbol == name` or where either
/// equals the empty description. One combined constant (plus the `u8`
/// decimals constant of a different type) can never produce a duplicate,
/// whatever the token metadata is. The on-chain `omni_bridge::deploy_token`
/// only inspects the resulting objects (`TreasuryCap` / `CoinMetadata` /
/// `UpgradeCap`), never the package source, so template provenance does not
/// matter for verification.
///
/// The compiled bytecode is vendored at `src/template/template_coin.mv`; see
/// `src/bytecode.rs` for how identifiers and constants are rewritten per
/// token. Regenerate with:
///   ~/.local/sui-cli/sui move build --dump-bytecode-as-base64
/// (or any sui CLI; run from this directory)
#[allow(deprecated_usage)]
module token_template::template_coin;

use sui::coin;

const DECIMALS: u8 = 9; // min(origin_decimals, 9), from the signed MetadataPayload
// [symbol, name, description]; symbol/name from the signed MetadataPayload.
const PARAMS: vector<vector<u8>> = vector[b"TMPL", b"Template Token", b""];

public struct TEMPLATE_COIN has drop {}

fun init(witness: TEMPLATE_COIN, ctx: &mut TxContext) {
    let params = PARAMS;
    let (treasury_cap, metadata) = coin::create_currency(
        witness,
        DECIMALS,
        *params.borrow(0), // symbol
        *params.borrow(1), // name
        *params.borrow(2), // description
        option::none(), // icon url
        ctx,
    );
    transfer::public_transfer(treasury_cap, ctx.sender());
    // NOT frozen: `deploy_token` takes the metadata by value and keeps it
    // bridge-owned so `set_token_metadata` can update it later.
    transfer::public_transfer(metadata, ctx.sender());
}
