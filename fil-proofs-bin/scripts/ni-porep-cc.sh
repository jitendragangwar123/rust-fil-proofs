#!/bin/sh
set -eu
set -o xtrace


# Usage help if nothing is piped in.
if [ -t 0 ]; then
    cat << EOF
Usage: echo '{}' | $(basename "${0}")

Perform a Non-interactive PoRep a single sector.

The input parameters are given by piping in JSON with the following keys:
 - output_dir: The directory where all files (layers as well as trees) are stored.
 - porep_id: The PoRep ID formatted in hex with leading 0x.
 - replica_id: The Replica ID formatted in hex with leading 0x.
 - sector_size: The size of the sector in bytes.
 - seed: The seed for creating the challenges for the Proof-of-replication.

Example JSON:
{
  "output_dir": "/path/to/some/dir",
  "porep_id": "0x0500000000000000000000000000000000000000000000000000000000000000",
  "replica_id": "0xd93f7c0618c236179361de2164ce34ffaf26ecf3be7bf7e6b8f0cfcf886ad000",
  "sector_size: "16384",
  "seed": "0xb59b73958d310335a3b43491e15221ed8f2d22c1b86e77ca53439ad5aed02e00"
}
EOF
     exit 1
fi


# Define default options for commands
CARGO="${CARGO:=cargo run --release}"
JQ='jq -r'
JO='jo --'

export FIL_PROOFS_USE_MULTICORE_SDR=1
export FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1
export FIL_PROOFS_USE_GPU_TREE_BUILDER=1
export FIL_PROOFS_VERIFY_CACHE=1
export RUST_LOG=trace


# Make sure all tools we need for this scripts are installed.
if ! command -v jq > /dev/null
then
    echo "'jq' not found." && exit 2
fi
if ! command -v jo > /dev/null
then
    echo "'jo' not found." && exit 3
fi


# Parse the input data.
read -r input_args
output_dir=$(echo "${input_args}" | ${JQ} '.output_dir')
porep_id=$(echo "${input_args}" | ${JQ} '.porep_id')
replica_id=$(echo "${input_args}" | ${JQ} '.replica_id')
sector_size=$(echo "${input_args}" | ${JQ} '.sector_size')
seed=$(echo "${input_args}" | ${JQ} '.seed')

if [ "${output_dir}" = 'null' ]; then
    echo "'output_dir' not set." && exit 4
fi
if [ "${porep_id}" = 'null' ]; then
    echo "'porep_id' not set." && exit 5
fi
if [ "${replica_id}" = 'null' ]; then
    echo "'replica_id' not set." && exit 6
fi
if [ "${sector_size}" = 'null' ]; then
    echo "'sector_size' not set." && exit 8
fi


# Get the default values for the given sector size.
default_values=$(jo sector_size="${sector_size}" | ${CARGO} --bin default-values)
>&2 echo "Default values: ${default_values}"
num_challenges_per_partition=$(echo "${default_values}" | ${JQ} '.num_challenges_per_partition')
num_layers=$(echo "${default_values}" | ${JQ} '.num_layers')
num_partitions=$(echo "${default_values}" | ${JQ} '.num_non_interactive_porep_partitions')
parameters_path=$(echo "${default_values}" | ${JQ} '.parameters_path')
srs_key_path=$(echo "${default_values}" | ${JQ} '.srs_key_path')
verifying_key_path=$(echo "${default_values}" | ${JQ} '.verifying_key_path')

mkdir -p "${output_dir}"

# It's a CC sctor, but we still need a TreeD.
unsealed_sector_path="${output_dir}/staged"
fallocate --length "${sector_size}" "${unsealed_sector_path}"
tree_d=$(${JO} input_path="${unsealed_sector_path}" output_dir="${output_dir}" sector_size="${sector_size}" | ${CARGO} --bin tree-d)
>&2 echo "TreeD: ${tree_d}"
comm_d=$(echo "${tree_d}" | ${JQ} '.comm_d')


# Run SDR.
sdr=$(${JO} num_layers="${num_layers}" output_dir="${output_dir}" -s porep_id="${porep_id}" -s replica_id="${replica_id}" sector_size="${sector_size}" | ${CARGO} --bin sdr)
>&2 echo "SDR: ${sdr}"


# Tree building for the coloumn commitment.
tree_c=$(${JO} input_dir="${output_dir}" num_layers="${num_layers}" output_dir="${output_dir}" sector_size="${sector_size}" | ${CARGO} --bin tree-c)
>&2 echo "TreeC: ${tree_c}"
comm_c=$(echo "${tree_c}" | ${JQ} '.comm_c')


# The sector key is the last layer of the SDR process.
sector_key_path="${output_dir}/sc-02-data-layer-${num_layers}.dat"


# Tree building for the replica commitment.
tree_r_last=$(${JO} output_dir="${output_dir}" replica_path="${sector_key_path}" sector_size="${sector_size}" | ${CARGO} --bin tree-r-last)
>&2 echo "TreeRLast: ${tree_r_last}"
comm_r_last=$(echo "${tree_r_last}" | ${JQ} '.comm_r_last')


# Calculate the resulting CommR.
comm_r_output=$(${JO} -s comm_c="${comm_c}" -s comm_r_last="${comm_r_last}" | ${CARGO} --bin comm-r)
>&2 echo "CommR: ${comm_r_output}"
comm_r=$(echo "${comm_r_output}" | ${JQ} '.comm_r')


# Generate the challenges.
challenges_path="${output_dir}/challenges-ni.json"
challenges_ni=$(${JO} -s comm_r="${comm_r}" num_challenges_per_partition="${num_challenges_per_partition}" num_partitions="${num_partitions}" -s replica_id="${replica_id}" sector_size="${sector_size}" | ${CARGO} --bin challenges-ni > "${challenges_path}")
>&2 echo "Challenges Ni: ${challenges_ni}"


# Generate merkle proofs.
vanilla_proofs_path="${output_dir}/porep-vanilla-proofs-ni.dat"
merkle_proofs=$(${JO} challenges="$(jq -c '.challenges' "${challenges_path}")" -s comm_c="${comm_c}" -s comm_d="${comm_d}" input_dir="${output_dir}" num_layers="${num_layers}" num_partitions="${num_partitions}" output_path="${vanilla_proofs_path}" -s porep_id="${porep_id}" -s replica_id="${replica_id}" -s replica_path="${sector_key_path}" sector_size="${sector_size}" -s seed="${seed}" | ${CARGO} --bin merkle-proofs)
>&2 echo "Merkle proofs: ${merkle_proofs}"


# Generate the SNARK.
snark_proofs_path="${output_dir}/snark-proof-ni-supraseal.dat"
snark_proof=$(${JO} -s comm_c="${comm_c}" -s comm_d="${comm_d}" -s comm_r="${comm_r}" -s comm_r_last="${comm_r_last}" num_challenges_per_partition="${num_challenges_per_partition}" num_layers="${num_layers}" num_partitions="${num_partitions}" output_path="${snark_proofs_path}" parameters_path="${parameters_path}" porep_proofs_path="${vanilla_proofs_path}" -s replica_id="${replica_id}" sector_size="${sector_size}" | ${CARGO} --bin snark-proof)
>&2 echo "SNARK proof: ${snark_proof}"


# Verify SNARK.
snark_proof_verify=$(${JO} -s comm_d="${comm_d}" -s comm_r="${comm_r}" input_path="${snark_proofs_path}" num_challenges_per_partition="${num_challenges_per_partition}" num_layers="${num_layers}" num_partitions="${num_partitions}" -s porep_id="${porep_id}" -s replica_id="${replica_id}" sector_size="${sector_size}" -s seed="${seed}" verifying_key_path="${verifying_key_path}" | ${CARGO} --bin snark-proof-verify)
>&2 echo "SNARK proof verify: ${snark_proof_verify}"


# Aggregate SNARK.
snark_proofs_aggregated_path="${output_dir}/snark-proof-aggregated-ni.dat"
snark_proof_aggregate=$(${JO} -s comm_r="${comm_r}" input_path="${snark_proofs_path}" num_proofs="${num_partitions}" output_path="${snark_proofs_aggregated_path}" -s seed="${seed}" srs_key_path="${srs_key_path}" | ${CARGO} --bin snark-proof-aggregate)
>&2 echo "SNARK proof aggregate: ${snark_proof_aggregate}"


# Verify aggregated SNARK.
snark_proof_aggregate_verify_ni=$(${JO} -s comm_d="${comm_d}" -s comm_r="${comm_r}" input_path="${snark_proofs_aggregated_path}" num_challenges_per_partition="${num_challenges_per_partition}" num_layers="${num_layers}" num_partitions="${num_partitions}" -s porep_id="${porep_id}" -s replica_id="${replica_id}" sector_size="${sector_size}" -s seed="${seed}" srs_key_path="${srs_key_path}" verifying_key_path="${verifying_key_path}" | ${CARGO} --bin snark-proof-aggregate-verify-ni)
>&2 echo "SNARK proof aggregate verify: ${snark_proof_aggregate_verify_ni}"

