// Counts the number of unique elements of a Synthetic PoRep proofs file.

use std::fs::File;

use anyhow::{Context, Result};
use fil_proofs_bin::cli;
use filecoin_hashers::poseidon::PoseidonHasher;
use filecoin_proofs::with_shape;
use log::info;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{merkle::MerkleTreeTrait, util::NODE_SIZE};
use storage_proofs_porep::stacked::SynthProofs;

// From `storage-proofs-porep/src/stacked/vanilla/challenges.rs`
const DEFAULT_SYNTH_CHALLENGE_COUNT: usize = 1 << 18;

/// Note that `comm_c`, `comm_d` and `comm_r_last` are not strictly needed as they could be read
/// from the generated trees. Though they are passed in for sanity checking.
#[derive(Debug, Deserialize, Serialize)]
struct MerkleProofsSynthCountParameters {
    num_layers: usize,
    sector_size: u64,
    synth_proofs_path: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct MerkleProofsSynthCountOutput {
    num_challenges: usize,
    num_total_nodes: usize,
    num_unique_nodes: usize,
    /// The size of a single challenge's serialized synthetic proof.
    single_proof_size: usize,
}

/// Returns the number of total and unique nodes are when all proofs are combined.
fn unique_nodes<Tree: MerkleTreeTrait>(
    num_layers: usize,
    sector_size: u64,
    synth_proofs_path: String,
) -> Result<(usize, usize)> {
    let mut file = File::open(&synth_proofs_path).with_context(|| {
        format!(
            "failed to open synthetic vanilla proofs file: {:?}",
            synth_proofs_path
        )
    })?;
    let proofs: Vec<storage_proofs_porep::stacked::Proof<Tree, PoseidonHasher>> =
        SynthProofs::read(
            &mut file,
            (sector_size as usize) / NODE_SIZE,
            num_layers,
            0..DEFAULT_SYNTH_CHALLENGE_COUNT,
        )?;
    SynthProofs::unique_nodes(&proofs)
}

fn proof_size<Tree: MerkleTreeTrait>(num_layers: usize, sector_size: u64) -> usize {
    SynthProofs::proof_size::<Tree>((sector_size as usize) / NODE_SIZE, num_layers)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: MerkleProofsSynthCountParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let (num_total_nodes, num_unique_nodes) = with_shape!(
        params.sector_size,
        unique_nodes,
        params.num_layers,
        params.sector_size,
        params.synth_proofs_path,
    )?;

    let single_proof_size = with_shape!(
        params.sector_size,
        proof_size,
        params.num_layers,
        params.sector_size,
    );

    let output = MerkleProofsSynthCountOutput {
        num_challenges: DEFAULT_SYNTH_CHALLENGE_COUNT,
        num_total_nodes,
        num_unique_nodes,
        single_proof_size,
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
