use anyhow::Result;
use blstrs::Scalar as Fr;
use ff::PrimeField;
use fil_proofs_bin::cli;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_porep::stacked::SynthChallenges;

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesSynthParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// The number of challenges to create.
    num_challenges: usize,
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
    /// Sector size is used to calculate the number of nodes.
    sector_size: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    seed: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesSynthOutput {
    challenges: Vec<usize>,
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: ChallengesSynthParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let sector_nodes = usize::try_from(params.sector_size)
        .expect("sector size must be smaller than the default integer size on this platform")
        / NODE_SIZE;
    let replica_id = Fr::from_repr_vartime(params.replica_id).expect("must be valid field element");
    let comm_r = Fr::from_repr_vartime(params.comm_r).expect("must be valid field element");
    let challenges =
        SynthChallenges::new(sector_nodes, &replica_id, &comm_r, params.num_challenges)
            .gen_porep_challenges(params.num_challenges, &params.seed);

    let output = ChallengesSynthOutput { challenges };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
