use alloy::{
    consensus::Header,
    eips::BlockNumberOrTag,
    network::Ethereum,
    primitives::{Address, B256, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
    transports::http::{reqwest::Url, Client, Http},
};
// use alloy_sol_types::{sol_data::Uint, SolType};
use anyhow::{bail, Result};
use op_alloy_network::{primitives::BlockTransactionsKind, EthereumWallet, Optimism};
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

sol! {
    type GameType is uint32;
    type Claim is bytes32;
    type Timestamp is uint64;

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    contract DisputeGameFactory {
        mapping(GameType => uint256) public initBonds;

        function gameCount() external view returns (uint256 gameCount_);

        function gameAtIndex(uint256 _index) external view returns (GameType gameType, Timestamp timestamp, IDisputeGame proxy);

        // extraData is a bytes array that contains the l2BlockNumber and parentIndex, and has length of 32 bytes and 4 bytes respectively
        function create(GameType gameType, Claim rootClaim, bytes extraData) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IDisputeGame {}

    #[allow(missing_docs)]
    #[sol(rpc)]
    contract OPSuccinctFaultDisputeGame {
        function l2BlockNumber() public pure returns (uint256 l2BlockNumber_);
    }
}

struct OPSuccicntProposer {
    l1_rpc: Url,
    l2_rpc: Url,
    l2_node_rpc: Url,
    wallet: EthereumWallet,
    factory_address: Address,
    last_proposed_block_number: u64,
    proposal_interval_in_blocks: u64,
    fetch_interval: u64,
    game_type: u32,
}

impl OPSuccicntProposer {
    pub async fn new() -> Result<Self> {
        let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
        let signer: PrivateKeySigner = private_key.parse().expect("Failed to parse private key");

        Ok(Self {
            l1_rpc: env::var("L1_RPC")
                .expect("L1_RPC must be set")
                .parse::<Url>()
                .unwrap(),
            l2_rpc: env::var("L2_RPC")
                .expect("L2_RPC must be set")
                .parse::<Url>()
                .unwrap(),
            l2_node_rpc: env::var("L2_NODE_RPC")
                .expect("L2_NODE_RPC must be set")
                .parse::<Url>()
                .unwrap(),
            wallet: EthereumWallet::from(signer),
            factory_address: env::var("FACTORY_ADDRESS")
                .expect("FACTORY_ADDRESS must be set")
                .parse::<Address>()
                .unwrap(),
            last_proposed_block_number: 0,
            proposal_interval_in_blocks: env::var("PROPOSAL_INTERVAL_IN_BLOCKS")
                .unwrap_or("1000".to_string())
                .parse::<u64>()
                .unwrap(),
            fetch_interval: env::var("FETCH_INTERVAL")
                .unwrap_or("30".to_string())
                .parse::<u64>()
                .unwrap(),
            game_type: env::var("GAME_TYPE")
                .unwrap_or("42".to_string())
                .parse::<u32>()
                .unwrap(),
        })
    }

    pub async fn get_safe_l2_head(&self) -> Result<Header> {
        let l2_provider: RootProvider<Http<Client>, Optimism> =
            ProviderBuilder::default().on_http(self.l2_rpc.clone());
        let block = l2_provider
            .get_block_by_number(BlockNumberOrTag::Safe, BlockTransactionsKind::Hashes)
            .await?;
        if let Some(block) = block {
            Ok(block.header.inner)
        } else {
            bail!("Failed to get safe L2 head");
        }
    }

    async fn fetch_last_game_index(&self) -> Result<U256> {
        let l1_provider: RootProvider<Http<Client>> =
            ProviderBuilder::default().on_http(self.l1_rpc.clone());
        let factory = DisputeGameFactory::new(self.factory_address, l1_provider.clone());
        let game_count = factory.gameCount().call().await?;
        let last_game_index = game_count.gameCount_ - U256::from(1);
        Ok(last_game_index)
    }

    async fn fetch_init_bond(&self) -> Result<U256> {
        let l1_provider: RootProvider<Http<Client>> =
            ProviderBuilder::default().on_http(self.l1_rpc.clone());
        let factory = DisputeGameFactory::new(self.factory_address, l1_provider.clone());
        let init_bond = factory.initBonds(self.game_type.into()).call().await?;
        Ok(init_bond._0)
    }

    async fn fetch_output_root_at_block(&self, l2_block_number: U256) -> Result<B256> {
        let l2_node_provider: RootProvider<Http<Client>, Optimism> =
            ProviderBuilder::default().on_http(self.l2_node_rpc.clone());
        let output_root = l2_node_provider
            .raw_request(
                "optimism_outputAtBlock".into(),
                vec![serde_json::json!(format!("0x{:x}", l2_block_number))],
            )
            .await?;
        Ok(output_root)
    }

    async fn fetch_l2_block_number(&self) -> Result<U256> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(self.wallet.clone())
            .on_http(self.l1_rpc.clone());
        let contract = DisputeGameFactory::new(self.factory_address, provider.clone());

        let last_game = contract
            .gameAtIndex(self.fetch_last_game_index().await?)
            .call()
            .await?;

        let last_game_address = last_game.proxy;
        tracing::info!("Last game proxy: {:?}", last_game_address);
        let last_game_proxy = OPSuccinctFaultDisputeGame::new(last_game_address, provider.clone());
        let last_game_l2_block_number =
            last_game_proxy.l2BlockNumber().call().await?.l2BlockNumber_;
        tracing::info!("Last game l2 block number: {:?}", last_game_l2_block_number);

        let l2_block_number =
            last_game_l2_block_number + U256::from(self.proposal_interval_in_blocks);
        Ok(l2_block_number)
    }

    async fn create_game(&self) -> Result<()> {
        const NUM_CONFIRMATIONS: u64 = 3;
        const TIMEOUT_SECONDS: u64 = 60;

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(self.wallet.clone())
            .on_http(self.l1_rpc.clone());
        let contract = DisputeGameFactory::new(self.factory_address, provider.clone());

        let last_game_index_u256 = self.fetch_last_game_index().await?;
        tracing::info!("Last game index: {:?}", last_game_index_u256);
        let l2_block_number = self.fetch_l2_block_number().await?;
        let last_game_index_u32 = last_game_index_u256.to::<u32>();
        let extra_data = <(U256, u32)>::abi_encode_packed(&(l2_block_number, last_game_index_u32));

        let receipt = contract
            .create(self.game_type.into(), B256::ZERO, extra_data.into())
            .value(self.fetch_init_bond().await?)
            .send()
            .await?
            .with_required_confirmations(NUM_CONFIRMATIONS)
            .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
            .get_receipt()
            .await?;

        tracing::info!("New game created at tx: {:?}", receipt.transaction_hash);

        Ok(())
    }

    async fn run(&mut self) -> Result<()> {
        let mut interval = time::interval(Duration::from_secs(self.fetch_interval));

        loop {
            interval.tick().await;

            let safe_l2_head_block_number = self.get_safe_l2_head().await?.number;
            tracing::info!("Safe L2 head block number: {:?}", safe_l2_head_block_number);

            if safe_l2_head_block_number
                > self.last_proposed_block_number + self.proposal_interval_in_blocks
            {
                self.create_game().await?;
                self.last_proposed_block_number += self.proposal_interval_in_blocks;
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with default level info
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    dotenv::dotenv().ok();

    let mut proposer = OPSuccicntProposer::new().await?;
    proposer.run().await
}
