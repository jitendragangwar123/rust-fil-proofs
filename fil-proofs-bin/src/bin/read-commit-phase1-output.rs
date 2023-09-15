use std::fs;

use anyhow::{Context, Result};
use bincode::deserialize;
use fil_proofs_bin::cli;
use filecoin_proofs::{with_shape, SealCommitPhase1Output};
use log::info;
use serde::{Deserialize, Serialize};
use storage_proofs_core::merkle::MerkleTreeTrait;

#[derive(Debug, Deserialize, Serialize)]
struct ReadCommitPhase1OutputParameters {
    commit_phase1_output_path: String,
    sector_size: u64,
}

fn deserialize_commit_phase1_output<Tree: MerkleTreeTrait>(
    commit_phase1_output_path: String,
) -> Result<()> {
    let commit_phase1_output_bytes = fs::read(&commit_phase1_output_path).with_context(|| {
        format!(
            "could not read file commit-phase1-output={:?}",
            commit_phase1_output_path
        )
    })?;
    let output: SealCommitPhase1Output<Tree> = deserialize(&commit_phase1_output_bytes)?;

    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: ReadCommitPhase1OutputParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    with_shape!(
        params.sector_size,
        deserialize_commit_phase1_output,
        params.commit_phase1_output_path,
    )
}
