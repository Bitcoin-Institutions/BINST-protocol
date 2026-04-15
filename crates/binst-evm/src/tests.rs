//! Integration tests for binst-evm (offline / unit tests only).
//!
//! RPC tests against live Citrea testnet are gated behind `#[ignore]`
//! — run them explicitly with `cargo test -- --ignored`.

#[cfg(test)]
mod offline {
    use crate::abi::*;
    use crate::types::*;

    #[test]
    fn finality_tier_proven() {
        let status = L2FinalityStatus {
            committed_height: 24_490_028,
            committed_batch_index: 17215,
            proven_height: 24_453_028,
            proven_batch_index: 17178,
        };
        assert_eq!(
            FinalityTier::classify(24_400_000, &status),
            FinalityTier::Proven
        );
    }

    #[test]
    fn finality_tier_committed() {
        let status = L2FinalityStatus {
            committed_height: 24_490_028,
            committed_batch_index: 17215,
            proven_height: 24_453_028,
            proven_batch_index: 17178,
        };
        assert_eq!(
            FinalityTier::classify(24_485_662, &status),
            FinalityTier::Committed
        );
    }

    #[test]
    fn finality_tier_soft() {
        let status = L2FinalityStatus {
            committed_height: 24_490_028,
            committed_batch_index: 17215,
            proven_height: 24_453_028,
            proven_batch_index: 17178,
        };
        assert_eq!(
            FinalityTier::classify(25_000_000, &status),
            FinalityTier::SoftConfirmation
        );
    }

    #[test]
    fn encode_decode_string_roundtrip() {
        let original = "0280ede1b09ceb87cdd661adb4a317d80586abf1576d7d869bc1cd177bfa7243i0";
        let encoded = encode_string(original);
        let decoded = decode_string(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_create_instance_starts_with_selector() {
        let names = vec!["Review".to_string(), "Approve".to_string()];
        let types = vec!["approval".to_string(), "approval".to_string()];
        let calldata = encode_create_instance("test_id", &names, &types).unwrap();
        assert!(calldata.starts_with("0x6f794b70"));
    }

    #[test]
    fn step_status_roundtrip() {
        assert_eq!(StepStatus::from_u8(0), Some(StepStatus::Pending));
        assert_eq!(StepStatus::from_u8(1), Some(StepStatus::Completed));
        assert_eq!(StepStatus::from_u8(2), Some(StepStatus::Rejected));
        assert_eq!(StepStatus::from_u8(3), None);
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod rpc_live {
    use crate::rpc::RpcClient;

    /// Live test against Citrea testnet — run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn citrea_testnet_block_number() {
        let client = RpcClient::new("https://rpc.testnet.citrea.xyz");
        let block = client.block_number().unwrap();
        assert!(block > 24_000_000, "Expected recent block, got {block}");
    }

    /// Live test: read the known factory instance count.
    #[test]
    #[ignore]
    fn citrea_testnet_instance_count() {
        let client = RpcClient::new("https://rpc.testnet.citrea.xyz");
        let factory = "0x6a1d2adbac8682773ed6700d2118c709c8ce5000";
        let count = client.get_instance_count(factory).unwrap();
        assert!(count >= 1, "Expected at least 1 instance, got {count}");
    }

    /// Live test: read the known instance's template inscription ID.
    #[test]
    #[ignore]
    fn citrea_testnet_template_inscription_id() {
        let client = RpcClient::new("https://rpc.testnet.citrea.xyz");
        let instance = "0x549049a68a0c006790f9671fc11bc8a37067f7c9";
        let id = client.get_template_inscription_id(instance).unwrap();
        assert!(id.contains('i'), "Expected inscription ID format, got: {id}");
    }

    /// Live test: finality status.
    #[test]
    #[ignore]
    fn citrea_testnet_finality() {
        let client = RpcClient::new("https://rpc.testnet.citrea.xyz");
        let status = client.get_finality_status().unwrap();
        assert!(status.committed_height > 0);
        assert!(status.proven_height > 0);
        assert!(status.committed_height >= status.proven_height);
    }
}
