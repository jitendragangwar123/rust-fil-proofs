use std::cmp;

use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_proofs::{
    LAYERS, POREP_MINIMUM_CHALLENGES, POREP_PARTITIONS, WINDOW_POST_SECTOR_COUNT,
};
use log::info;
use serde::{Deserialize, Serialize};
use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_porep::stacked::DEFAULT_SYNTH_CHALLENGE_COUNT;

#[derive(Debug, Deserialize, Serialize)]
struct DefaultValuesParameters {
    sector_size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct DefaultValuesOutput {
    num_layers: usize,
    num_porep_challenges: usize,
    num_porep_partitions: u8,
    num_synth_porep_challenges: usize,
    num_window_post_sectors: usize,
}

const fn next_multiple_of(base: usize, multiple: usize) -> usize {
    match base % multiple {
        0 => base,
        rest => base + (multiple - rest),
    }
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: DefaultValuesParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let num_layers = *LAYERS
        .read()
        .expect("LAYERS poisoned")
        .get(&params.sector_size)
        .expect("unknown sector size");
    let num_porep_partitions = *POREP_PARTITIONS
        .read()
        .expect("POREP_PARTITIONS poisoned")
        .get(&params.sector_size)
        .expect("unknown sector size");
    let num_window_post_sectors = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&params.sector_size)
        .expect("unknown sector size");
    let num_porep_minimum_challenges =
        POREP_MINIMUM_CHALLENGES.from_sector_size(params.sector_size);
    let num_porep_challenges =
        next_multiple_of(num_porep_minimum_challenges, num_porep_partitions.into());
    let sector_nodes = params.sector_size as usize / NODE_SIZE;
    let num_synth_porep_challenges = cmp::min(sector_nodes, DEFAULT_SYNTH_CHALLENGE_COUNT);

    let output = DefaultValuesOutput {
        num_layers,
        num_porep_challenges,
        num_porep_partitions,
        num_window_post_sectors,
        num_synth_porep_challenges,
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
