use std::{
    alloc::System,
    borrow::BorrowMut,
    cell::RefCell,
    fs::{self, File},
    path::Path,
    rc::Rc,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use bellperson::groth16;
use blstrs::Bls12;
use fil_proofs_bin::cli;
use filecoin_proofs::{proofs_to_bytes, with_shape, DefaultPieceHasher};
use log::info;
use rand::rngs::OsRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{merkle::MerkleTreeTrait, parameter_cache, util::NODE_SIZE};
use storage_proofs_porep::stacked::{StackedCircuit, SynthProofs};
use tracking_allocator::{
    AllocationGroupId, AllocationRegistry, AllocationTracker, Allocator,
};

#[global_allocator]
static GLOBAL: Allocator<System> = Allocator::system();

/// The number of circuits that will be synthesized in one batch.
///
/// This is memory heavy operation, hence we don't always use a single batch only.
const GROTH16_BATCH_SIZE: usize = 10;

/// At which difference of memory usage it's being printed.
const TRACKER_THRESHOLD: usize = 5 * 1024 * 1024;

struct StdoutTracker {
    //total: Rc<RefCell<usize>>,
    total: Arc<Mutex<usize>>,
    counter: Arc<Mutex<usize>>,
    prev_printed: Arc<Mutex<usize>>,
}

impl StdoutTracker {
    pub fn new() -> Self {
        Self {
            total: Arc::new(Mutex::new(0)),
            counter: Arc::new(Mutex::new(0)),
            prev_printed: Arc::new(Mutex::new(0)),
        }
    }
}

// This is our tracker implementation.  You will always need to create an implementation of `AllocationTracker` in order
// to actually handle allocation events.  The interface is straightforward: you're notified when an allocation occurs,
// and when a deallocation occurs.
impl AllocationTracker for StdoutTracker {
    fn allocated(
        &self,
        addr: usize,
        object_size: usize,
        wrapped_size: usize,
        group_id: AllocationGroupId,
    ) {
        // Allocations have all the pertinent information upfront, which you may or may not want to store for further
        // analysis. Notably, deallocations also know how large they are, and what group ID they came from, so you
        // typically don't have to store much data for correlating deallocations with their original allocation.
        //println!(
        //    "allocation -> addr=0x{:0x} object_size={} wrapped_size={} group_id={:?}",
        //    addr, object_size, wrapped_size, group_id
        //);
        **self.counter.lock().unwrap().borrow_mut() += 1;
        **self.total.lock().unwrap().borrow_mut() += wrapped_size;

        let total = *self.total.lock().unwrap();
        if *self.counter.lock().unwrap() % 100000 == 0 {
            let prev_printed = *self.prev_printed.lock().unwrap();
            if prev_printed < total - TRACKER_THRESHOLD || prev_printed > total + TRACKER_THRESHOLD {
                println!("vmx: currently allocated: {:?} MiB", total / 1024 / 1024);
                **self.prev_printed.lock().unwrap().borrow_mut() = total;
            }
        }
    }

    fn deallocated(
        &self,
        addr: usize,
        object_size: usize,
        wrapped_size: usize,
        source_group_id: AllocationGroupId,
        current_group_id: AllocationGroupId,
    ) {
        // When a deallocation occurs, as mentioned above, you have full access to the address, size of the allocation,
        // as well as the group ID the allocation was made under _and_ the active allocation group ID.
        //
        // This can be useful beyond just the obvious "track how many current bytes are allocated by the group", instead
        // going further to see the chain of where allocations end up, and so on.
        //println!(
        //    "deallocation -> addr=0x{:0x} object_size={} wrapped_size={} source_group_id={:?} current_group_id={:?}",
        //    addr, object_size, wrapped_size, source_group_id, current_group_id
        //);
        **self.total.lock().unwrap().borrow_mut() -= wrapped_size;
    }
}


/// Note that `comm_c` and `comm_d` are not strictly needed as they could be read from the
/// generated trees. Though they are passed in for sanity checking.
#[derive(Debug, Deserialize, Serialize)]
struct SnarkProofParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_c: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r_last: [u8; 32],
    num_challenges_per_partition: usize,
    num_layers: usize,
    num_partitions: usize,
    /// The path to the file the proofs should be stored into.
    output_path: String,
    /// Path to the Filecoin Groth16 parameter file the corresponds to the given sector size.
    parameters_path: String,
    /// The file that contains the merkle proofs.
    porep_proofs_path: String,
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
    sector_size: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct SnarkProofOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

#[allow(clippy::too_many_arguments)]
fn snark_proof<Tree: 'static + MerkleTreeTrait>(
    comm_c: [u8; 32],
    comm_d: [u8; 32],
    comm_r: [u8; 32],
    comm_r_last: [u8; 32],
    num_challenges_per_partition: usize,
    num_layers: usize,
    num_partitions: usize,
    parameters_path: String,
    porep_proofs_path: String,
    replica_id: [u8; 32],
    sector_size: u64,
) -> Result<Vec<u8>> {
    let mut file = File::open(&porep_proofs_path)
        .with_context(|| format!("failed to open porep proofs={:?}", porep_proofs_path))?;

    let sector_nodes = (sector_size as usize) / NODE_SIZE;
    let num_challenges = num_challenges_per_partition * num_partitions;
    let vanilla_proofs = SynthProofs::read::<Tree, DefaultPieceHasher, _>(
        &mut file,
        sector_nodes,
        num_layers,
        0..num_challenges,
    )
    .with_context(|| format!("failed to read porrep proofs={:?}", porep_proofs_path,))?;

    // TODO vmx 2023-10-20: All this splitting into partitions and chunks is confusion, make the
    // cdoe easier to understand.

    // The proofs are split into partitions, hence organize them in those partitions.
    let vanilla_proofs_partitions = vanilla_proofs
        .chunks_exact(num_challenges_per_partition)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();

    // The following is kind of a re-implementation of `StackedCompund::circuit_proofs()`. The
    // reason to not use it directly is that it needs `SetupParams`, although the only value
    // it needs is the number of layers. Instead of passing in dummy values, just re-implment it
    // here.

    // This is the same what `StackedCircuit::circuit()` does.
    let circuits = vanilla_proofs_partitions
        .into_par_iter()
        .map(|vanilla_proof| {
            let proofs = vanilla_proof.iter().cloned().map(|p| p.into()).collect();
            StackedCircuit::new(
                replica_id.into(),
                comm_d.into(),
                comm_r.into(),
                comm_r_last.into(),
                comm_c.into(),
                num_layers,
                proofs,
            )
        })
        .collect::<Vec<_>>();

    let groth_params = parameter_cache::read_cached_params(Path::new(&parameters_path))?;

    let mut rng = OsRng;
    // The proof synthesis takes a lot of memory and is highly parallelized. Hence process it in
    // chunks to reduce the maximum memory consuption.
    let groth_proofs = circuits
        .chunks(GROTH16_BATCH_SIZE)
        .flat_map(|circuits_chunk| {
            groth16::create_random_proof_batch_in_priority(
                circuits_chunk.to_vec(),
                &groth_params,
                &mut rng,
            )
        })
        .flatten();

    let groth_proofs_result = groth_proofs
        .map(|groth_proof| {
            let mut proof_vec = Vec::new();
            groth_proof.write(&mut proof_vec)?;
            let gp = groth16::Proof::<Bls12>::read(&proof_vec[..])?;
            Ok(gp)
        })
        .collect::<Result<Vec<_>>>()?;

    let proofs_bytes = proofs_to_bytes(&groth_proofs_result)?;
    Ok(proofs_bytes)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let _ = AllocationRegistry::set_global_tracker(StdoutTracker::new())
        .expect("no other global tracker should be set yet");
    AllocationRegistry::enable_tracking();

    let params: SnarkProofParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let proofs = with_shape!(
        params.sector_size,
        snark_proof,
        params.comm_c,
        params.comm_d,
        params.comm_r,
        params.comm_r_last,
        params.num_challenges_per_partition,
        params.num_layers,
        params.num_partitions,
        params.parameters_path,
        params.porep_proofs_path,
        params.replica_id,
        params.sector_size,
    )?;

    fs::write(&params.output_path, proofs)?;

    let output = SnarkProofOutput::default();
    info!("{:?}", output);
    cli::print_stdout(output)?;

    AllocationRegistry::disable_tracking();

    Ok(())
}
