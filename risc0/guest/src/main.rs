#![no_std]
#![no_main]

use risc0_zkvm::guest::env;

risc0_zkvm::entry!(main);

fn main() {
    let input: Vec<u8> = env::read();
    
    env::commit(&input);
} 