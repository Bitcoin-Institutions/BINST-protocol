//! Integration tests for binst-btc.

#[cfg(test)]
mod offline {
    use crate::types::*;

    #[test]
    fn btc_network_mempool_urls() {
        assert!(BtcNetwork::Testnet4.mempool_api_base().contains("testnet4"));
        assert!(BtcNetwork::Signet.mempool_api_base().contains("signet"));
        assert!(!BtcNetwork::Mainnet.mempool_api_base().contains("testnet"));
    }

    #[test]
    fn confirmation_status_eq() {
        assert_eq!(ConfirmationStatus::Mempool, ConfirmationStatus::Mempool);
        assert_eq!(
            ConfirmationStatus::Confirmed { confirmations: 6 },
            ConfirmationStatus::Confirmed { confirmations: 6 },
        );
        assert_ne!(ConfirmationStatus::Mempool, ConfirmationStatus::NotFound);
    }
}
