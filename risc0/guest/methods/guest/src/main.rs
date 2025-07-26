use risc0_zkvm::guest::env;

fn main() {
    let input: u32 = env::read();

    let result = input * input;

    let output = (input, result);
    
    env::commit(&output);
}
