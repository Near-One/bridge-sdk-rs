# PR #183 Feedback: Error Handling Extensions #

### PR Feedback
> "same kind of fixes"

### Identified Candidates for Similar Improvements

#### 1. **CLI Command Hash Parsing (Highest Priority)**
**File**: `bridge-cli/src/omni_connector_command.rs`

**Current `.expect()` calls found:**
```rust
// Line 391: Ethereum TxHash parsing
tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),

// Line 412: NEAR CryptoHash parsing  
near_tx_hash: CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),

// Line 514: Ethereum TxHash parsing
tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),

// Line 592: NEAR CryptoHash parsing
near_tx_hash: CryptoHash::from_str(&tx_hash).expect("Invalid tx_hash"),

// Line 679: Ethereum TxHash parsing
tx_hash: TxHash::from_str(&tx_hash).expect("Invalid tx_hash"),
```

#### **Main.rs Configuration Handling **
**File**: `bridge-cli/src/main.rs`

**Current `.expect()` calls found:**
```rust
// Line 400: File opening
let file = File::open(path).expect("Unable to open config file");

// Line 403: JSON parsing
serde_json::from_reader(reader).expect("Unable to parse config file");

// Line 467: Logger setup
tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
```


#### Crypto Utils Error Handling

- File: bridge-sdk/crypto-utils/src/lib.rs
- Lines 11 & 15: Cryptographic constant parsing
- Before/After code: Shows .unwrap() for error
 handling



#### Solana Bridge Client

- File: bridge-sdk/bridge-clients/solana-bridge-client/sr
  c/solana_bridge_client.rs
- Line 298: Base58 decoding
- Before/After code: Shows .unwrap() to error handling
conversion

