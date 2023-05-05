use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::sha256::Sha256Domain;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_porep::stacked::InteractivePoRep;

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesParameters {
    /// The total number of challenges to create.
    num_challenges: usize,
    /// Total number of challenges.
    num_partitions: usize,
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

    assert_eq!(
        params.num_challenges % params.num_partitions,
        0,
        "Number of challenges must be divisible by the number of partitions"
    );
    let num_challenges = params.num_challenges / params.num_partitions;
    let challenges = InteractivePoRep::new(num_challenges);
    let sector_nodes = usize::try_from(params.sector_size)
        .expect("sector size must be smaller than the default integer size on this platform")
        / NODE_SIZE;

    let challenge_positions = (0..params.num_partitions)
        .flat_map(|k| {
            challenges.derive::<Sha256Domain>(
                sector_nodes,
                &params.replica_id.into(),
                &params.seed,
                k as u8,
            )
        })
        .collect::<Vec<usize>>();

    let output = ChallengesOutput {
        challenges: challenge_positions,
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
