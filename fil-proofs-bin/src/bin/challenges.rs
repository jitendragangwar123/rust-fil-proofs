use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::sha256::Sha256Domain;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_porep::stacked::LayerChallenges;

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesParameters {
    /// The number of challenges to create.
    num_challenges: usize,
    num_partitions: u8,
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
    /// Sector size is used to calculate the number of nodes.
    sector_size: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    seed: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesOutput {
    challenges: Vec<usize>,
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: ChallengesParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let leaves = usize::try_from(params.sector_size)
        .expect("sector size must be smaller than the default integer size on this platform")
        / NODE_SIZE;
    let layer_challenges = LayerChallenges::new(params.num_challenges);
    let challenges = layer_challenges.derive::<Sha256Domain>(
        leaves,
        &params.replica_id.into(),
        // For normal PoRep this value isn't used, so we can put in an arbitrary value.
        &[1u8; 32].into(),
        &params.seed,
        params.num_partitions,
    );

    let output = ChallengesOutput { challenges };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
