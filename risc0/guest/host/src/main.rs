use methods::{
    GUEST_CODE_FOR_ZK_PROOF_ELF, GUEST_CODE_FOR_ZK_PROOF_ID
};
use risc0_zkvm::{default_prover, ExecutorEnv};
use bincode;
use std::fs;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    let input: u32 = 5; 
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    let prove_info = prover
        .prove(env, GUEST_CODE_FOR_ZK_PROOF_ELF)
        .unwrap();

    let receipt = prove_info.receipt;

    let proof_bytes = bincode::serialize(&receipt).unwrap();

    fs::write("proof.bin", &proof_bytes).unwrap();
    println!("Proof saved to proof.bin");

    let method_id_bytes = bincode::serialize(&GUEST_CODE_FOR_ZK_PROOF_ID).unwrap();
    fs::write("method_id.bin", method_id_bytes).unwrap();
    let output: (u32, u32) = receipt.journal.decode().unwrap();
    println!("input: {}", output.0);
    println!("Result (square): {}", output.1);
}
