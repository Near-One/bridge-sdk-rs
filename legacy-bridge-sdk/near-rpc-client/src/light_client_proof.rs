use near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofResponse;
use near_primitives::borsh::{BorshDeserialize, BorshSerialize};

// This code adjusts the struct `RpcLightClientExecutionProofResponse`
// by removing some fields that are incompatible with the bridge proof

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ExecutionOutcomeView {
    pub logs: Vec<String>,
    pub receipt_ids: Vec<near_primitives::hash::CryptoHash>,
    pub gas_burnt: near_primitives::types::Gas,
    pub tokens_burnt: near_primitives::types::Balance,
    pub executor_id: near_primitives::types::AccountId,
    pub status: near_primitives::views::ExecutionStatusView,
    // pub metadata: ExecutionMetadataView, incompatible with bridge proof
}

impl From<near_primitives::views::ExecutionOutcomeView> for ExecutionOutcomeView {
    fn from(item: near_primitives::views::ExecutionOutcomeView) -> Self {
        Self {
            logs: item.logs,
            receipt_ids: item.receipt_ids,
            gas_burnt: item.gas_burnt,
            tokens_burnt: item.tokens_burnt,
            executor_id: item.executor_id,
            status: item.status,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ExecutionOutcomeWithIdView {
    pub proof: near_primitives::merkle::MerklePath,
    pub block_hash: near_primitives::hash::CryptoHash,
    pub id: near_primitives::hash::CryptoHash,
    pub outcome: ExecutionOutcomeView,
}

impl From<near_primitives::views::ExecutionOutcomeWithIdView> for ExecutionOutcomeWithIdView {
    fn from(item: near_primitives::views::ExecutionOutcomeWithIdView) -> Self {
        Self {
            proof: item.proof,
            block_hash: item.block_hash,
            id: item.id,
            outcome: item.outcome.into(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct LightClientBlockLiteView {
    pub prev_block_hash: near_primitives::hash::CryptoHash,
    pub inner_rest_hash: near_primitives::hash::CryptoHash,
    pub inner_lite: BlockHeaderInnerLiteView,
}

impl From<near_primitives::views::LightClientBlockLiteView> for LightClientBlockLiteView {
    fn from(item: near_primitives::views::LightClientBlockLiteView) -> Self {
        Self {
            prev_block_hash: item.prev_block_hash,
            inner_rest_hash: item.inner_rest_hash,
            inner_lite: item.inner_lite.into(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct BlockHeaderInnerLiteView {
    pub height: near_primitives::types::BlockHeight,
    pub epoch_id: near_primitives::hash::CryptoHash,
    pub next_epoch_id: near_primitives::hash::CryptoHash,
    pub prev_state_root: near_primitives::hash::CryptoHash,
    pub outcome_root: near_primitives::hash::CryptoHash,
    // pub timestamp: u64, incompatible with bridge proof
    pub timestamp_nanosec: u64,
    pub next_bp_hash: near_primitives::hash::CryptoHash,
    pub block_merkle_root: near_primitives::hash::CryptoHash,
}

impl From<near_primitives::views::BlockHeaderInnerLiteView> for BlockHeaderInnerLiteView {
    fn from(item: near_primitives::views::BlockHeaderInnerLiteView) -> Self {
        Self {
            height: item.height,
            epoch_id: item.epoch_id,
            next_epoch_id: item.next_epoch_id,
            prev_state_root: item.prev_state_root,
            outcome_root: item.outcome_root,
            timestamp_nanosec: item.timestamp_nanosec,
            next_bp_hash: item.next_bp_hash,
            block_merkle_root: item.block_merkle_root,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct LightClientExecutionProof {
    pub outcome_proof: ExecutionOutcomeWithIdView,
    pub outcome_root_proof: near_primitives::merkle::MerklePath,
    pub block_header_lite: LightClientBlockLiteView,
    pub block_proof: near_primitives::merkle::MerklePath,
}

impl From<RpcLightClientExecutionProofResponse> for LightClientExecutionProof {
    fn from(item: RpcLightClientExecutionProofResponse) -> Self {
        Self {
            outcome_proof: item.outcome_proof.into(),
            outcome_root_proof: item.outcome_root_proof,
            block_header_lite: item.block_header_lite.into(),
            block_proof: item.block_proof,
        }
    }
}

#[test]
fn test_decode_encode_valid_proofs() {
    // The proofs are copied from existing eth transactions
    // https://etherscan.io/tx/0xf576fa11605981ce96024aad2f8212449d0b14f2b8d3fb1fad858805fd50f05f
    // https://etherscan.io/tx/0xdb8aaaba5f2787c373f6a54ac52b16173d6c79e13c2b9f1c0c84db49f9cc300a
    // https://etherscan.io/tx/0x4650b4da59574123612841a785597ad58822f521ff073a5ba0d8fd8361e47b42
    let proofs = [
        "020000005e508ff7c443d5b50c6002e18698acb974aa787950a1788fd5a4121cff299dfe00327c4b5bdc0b399318889b979ada65e1dd284ac417297e43b4c9584745d99acc01db3cb0bde4f8d6c752e58b1c4e71c7c5f0a4b56d4fcaeca475af4ff91ce11c481e5ab6083082023d3d117dc732c22edf8041c01364bf8bbc3d8299a0ac6a46e10000000001000000cbd4e40e62cd25c357c11d59c48084e703c90bbf451393d175252ecd4de9a5e760a6d0881e03000000601a7c2ed9a297120000000000000013000000666163746f72792e6272696467652e6e65617202390000000000004833ec95d0a2b0410100000000001ab43204a195a0fd37edec621482afd3792ef90bd95d47e2f7723d463d585c774a3f020836b6dcf2020000001154499f75c1816dc1fbe9e92d31400141a768c9394eb5263c0ad3e10eb5dc5101c1c5519c354ede01da25441900986024caa821f4bb5ab920c728a31f04597d5500afe3b47a0c2107f01ddd71372a940df106fd5112603df03f8b12b879b9aa008378b5021678e9889d53a02f16628db0bdad9fded45b9abcfad916b3ea1b9f393f5cb14f0500000000e5283a3e7e03a688254e57545c8ed7325b78f60a95df2e3b72af964023e585eaf097c06b12d07e84e373f3d3d07ab16f23b65ae33779160c7589659b1d1c310f71154727d58b728acccac5065db95f3925451b10e029bd8b30c892a258e1aff8ee15886fbaf11fb269dd7f80d748a6e4c0ac62bebaabd7b31005717a90c311d5938ccea0cef8531720647af43c804d99ba004c47264e195136d801b914aceaa5d0d2fa878fbc1b1dfc74b7649a1089b92e030d0731bd4e2b0f37348d6c7884c2ee748a51c4f6812e160000006fc13ada9a1958e3d04a540957e46d7296903750611da0833b61f763e68d36670136a3aa64d2a1b4e57f34f031db1484cca25f0b478dc931cc250da68352399fb7014ed9a48f0cd63c7568d7ef944ffba3a9808671e42b75a67129bc9e0d522c646700fb507a56c7cf84002e4a045cace86e85abeb3647ab68392e4db50109d908704c01c8d1b76daa34a0d9feed9c49e3a3cb0983749f81d8c372aac2aff7f3c7740d6600bf2a0a0f2d1f57b64eeb488b1a8506584414f58534ac50faf89a648fde849625007f2b40cd7e64698f0cde0c4b90e9b68544167c16cfbcdeb6d72942e4bfd20508003c7a6b9d8e5cbbe39beec0b1b6b96890d321c8490708f1694d6fba222622145800b91d6ffcf022a39397b3a49ae837cc5d246ceb1a56f2e99867417a9625a5b65a0021d62d3b69d16bffe63174fdd6767b07d78fac3cae4846fa02c0536059dbd3f2007650bcff061864291d7c4ca8405c6760f534f52055a5520246111f7616c67c7f0011cd985c0f575e95a0fb9a2dd29351c5ef35a4c39f59cb56f5883c72a237a94500a5ad33d3e01ea1fe6d0e9861a0f80b813571105b4a1c3f3efcf3eb162ab8cad700ab0b126c19a104716035f4d82be744a2c388d154b79634356f7b09d56df9596f014202e9e6efe3752e0c3995e4cb0519e78596dd2567abfe3902a6c3f7041129d3005953312d4d0c204b6edbbe4f99ca8c70506a57fc14c4a46e61fd800d4a06515e01da44666a5bbd4b1d6882b4bb838b31039a3fd09852f988832ed75b4ea4cda43a005dc1cd120103a509616611e5c338e8e9ee2b19b8a7b65edb90a87ae218be03ca00a32cbafcd86c9c7e723034593e854d780d84af392c80a8284956808810298f020099799018ae53afdfd39104625933e989aa6e848ff4ae4dd7a5c5a18f299ea427002a5586089ed83fc8056461874108819e061e9b6e2f5023f38048e9dc5247033800124bb839a5b9c44856054c6d80bd5229ac2b40fa8a0cd44911629f295b11f08200",
        "01000000afea2ed68789f84a99f4f34c8d52a3843aa218b3d3693121852a2237d35027790106fb1c577cd08b484656dfd2f72e99f1be9c48e0e39cd1b1dcf7b35db063fb42856b48c6cf0879c68375aa5544b19207d57c430054730aa2d150e3337d0e02b50000000001000000fb554a44b43f288b73e7a347f8cb6c9752bb19a1f8b1d6cddf18b53f212f3d305fbe22624d030000007f3c95389ce0ae1300000000000000060000006175726f72610238000000802eccc049848d040000000000000000e6d05d4c47a7aaa3fed6b3006dcd80289e1b33576bfad42cfc4efc96f529d786d643ff4a8b89fa52020000001768434c0c308f40465eaf3b4ee7968c4d8bd72a7d7d1793b2ea2de3c08082f200a8ac80cf4e3a3ad020855c28a6ee0428eea051fe0668913b39fd650f1e066fb80195bd642e1c3b9cd588336007229214f147c16a3d02441d354e3f9626f350e4fcef2a92d2f4eeb3f5ab51204c94b2cc778c1b7e1ccc332dd3f1ac61e5265d56df83ff4f0500000000e5283a3e7e03a688254e57545c8ed7325b78f60a95df2e3b72af964023e585eaf097c06b12d07e84e373f3d3d07ab16f23b65ae33779160c7589659b1d1c310f0c9a02ad19c1197f956eb2f9ab5c19db100d45b5b63fdd5ade48706e6f826e1368681a19114b66b27c2dd035e64363888e7545a0edb29477d9825448fde46ebc61e94b5c790d541720647af43c804d99ba004c47264e195136d801b914aceaa5d0d2fa878fbc1b1db692b16d8419acb806def2a51547e28f8b56ba351024272ecd0295f7b9e87222160000004144f86ba801e585abe16448b21a39704e4b04c9aafd4695802d1a620b27647a01a33bdbfb627033c60988dd43141bac07a3ff8d3f232e140680dffed387b78080003586a2efded869f58700896a97014f5cd1e9c69dddf523d530a7fffe1bedb98801e562334ef1f1a241a912fa3a8648227950fbe6afee13d0bf53d9d9b56047349100775b0b07ccb778ba3040aaf21d72bc32e5dc6f496205b7cbb51958dcb79889cb00264ebbfc35522a10c48828671c1383287e47fe293c1b4cbf95a34a7adf90f9e301794310a080fb13ae463bc8e90911abf119f097cea3af75acb6537744f2511241015ba21fa827f774f462a011ac40ce11b2d194d5d998fb100f8b863dd9f1043179013676332fe59fbc097acd3800f4fba39b62f3162e26f291a113c00084116f67010110dbc392e2bf1b915549bcc120fafbe08e7f1baaeaaf2de8f1f107e8afd4907a00d2b838c911c61bf3f56a10300e033d1c9a0efd865c02be3e2c90f4502218911900cdd70f33fcd4fff6389fed137e8a9440fe5fa97606f22edd90549b99ca8cf6d400fc30a32980d1fad0b3d5b45d781a2c7ec82b43991c051acf42547d23cad39520017d6998f2f486d3d4d32e17187497e1e8b6ee147de757b1234ed46714b92f623e00492209bfbc617d5e8abab16c3a120566fe32d6a9b03f6f30049b6297a276410201ce1bd3afe7ae7918d6e31172aa08819e460e2163006abc4c1b65bf0dc68cdf6b00da44666a5bbd4b1d6882b4bb838b31039a3fd09852f988832ed75b4ea4cda43a005dc1cd120103a509616611e5c338e8e9ee2b19b8a7b65edb90a87ae218be03ca00a32cbafcd86c9c7e723034593e854d780d84af392c80a8284956808810298f020099799018ae53afdfd39104625933e989aa6e848ff4ae4dd7a5c5a18f299ea427002a5586089ed83fc8056461874108819e061e9b6e2f5023f38048e9dc5247033800124bb839a5b9c44856054c6d80bd5229ac2b40fa8a0cd44911629f295b11f08200",
        "01000000e751017764a9b5bcfb6b6d9b47ecb54334336ff85f0aacaf8883f5e7b870630f0036fa7b087e4fdf1a91bbcdebc418d13caad8b1c5555e46d04350a473d4a9b29198a294e771d26345f54bf2e95b38920ccddd74f295721e1b07b8991a0eec2e040000000001000000dfdf11d08a93621b61723ff0a1a532747f896a9b448c9342d26f59801c4687676c3940109902000000ecd382de55167c0f000000000000000b000000652d6e6561722e6e656172022500000000c08dae4389a7428edd6f700000000000b78e3e8bd36b3228322d0a9d3271b5fbb7997fa302000000fb462cb41aecb8f4f71a871cf88c7d144c3d24c475cd975c2ef696eec129594d01dc3bc1738a6c0f4abdf4b35185454c11100f51b5996ca882f45f0159dd6811f9003425cd79ab39960acc07f122b61c9e43d3170da4651817fa2ef2445f8862f671642003eac3394a854e6d9be7986fb8e15354e34c1385c30acbd62d9c937f526583054b0500000000ebc4e5cd92013be0d132d33898200a88a0728bc6b037bc9211f95957b477aca9646b6a37e2a0b80caba484876f15576a468851a6a7c821e5e295603fb7f1457e4a191c50f3131ce030205c5233aa6be44181435bd55b5d2a484fdf454a0bd32cecd911448618f54fb8a560e8d0e1591aeb97f2117514f641bc6d35d10d998b0e124422df02be5217b5f333f4ec3705f00db333069c4b99e71debb76009ed4014ed9d81d1bcfb4d83fd2344f017bdc864fb35378d8622265213bba08958621db2854533100f7a07d4170000003425cd79ab39960acc07f122b61c9e43d3170da4651817fa2ef2445f8862f6710039850b8aad93767bba1f16f4a71c4ebafa687f86e48fa16143c1d4f2c7a6c54a019a853ba1fe7ef179862fa355d0dbd4db2026c8330a8db5ad34ed6df733f7700b00297919b499fa8c6acb0cf9e9858443a90ee02d4ee85feb52d97ef108c59e892d00fc1540226be3fa06fcba26491e95c3654b38aa684da2c37df8665c25e329851200c26bd0ce96bb2eec85263898e7e410d122a523173f753027cba8da57502a9d7e01722aa8dc8645184dcbf6da20ac9b85d58cfbffada2240e7dcb7e8a3298a4f8da00c6c585b3950faae2b15df12744c1342f5810bf59031e5e09e5f0eeb816b81c7701921d88b1ebc3bd74ae84e0982b1fb4be2aaae1e04c05d06e1386f75c5f8f0653012012a0b59f3d5c4aaf987987db4d547f1c5b0a2c8944997d85734c0a159f7600012151fe9ee36a268be56a553fc25e84cabc35ca5e134a066bfa601609c713285a00363cb263c4a929498fc0261481da59ddeacf582049029ba9d34cc381c2e34896014a3051a8277bc78371b7f6ec19810b195e81c8e7a2a4e4a6948fa9b4f7b4123400b528225710d1637d6bba0d74e6457feab856627237934e0965912445fac92577004a9256e07e92042b27f0f9f94c53528ab4c766359e305bea0e0d3d9f33e54a210138997866f109830acaca63453bdcb95a1e070a074df0cc1afb8da96f49a2b3390003f01518fd3fbb272a93c01d65448ba65a171ee5a5dda849aec255314b52149f005104dc6bfdd341db39000aca8f55f2437800a161dd33db1cd73c225a52d4a6ec013aa279bd7699402f6bb04be8bfebd903a3fa6328d78b738794b327b4522f1a7001a32cbafcd86c9c7e723034593e854d780d84af392c80a8284956808810298f020099799018ae53afdfd39104625933e989aa6e848ff4ae4dd7a5c5a18f299ea427002a5586089ed83fc8056461874108819e061e9b6e2f5023f38048e9dc5247033800124bb839a5b9c44856054c6d80bd5229ac2b40fa8a0cd44911629f295b11f08200"
    ];
    for hex_proof in proofs {
        let bytes_proof = hex::decode(hex_proof).unwrap();
        let decoded_proof =
            LightClientExecutionProof::try_from_slice(bytes_proof.as_slice()).unwrap();
        let mut encoded_proof = Vec::new();
        decoded_proof.serialize(&mut encoded_proof).unwrap();
        assert_eq!(encoded_proof, bytes_proof);
    }
}
