//! A simple script to generate and verify the proof of a given program.
use sp1_sdk::{include_elf, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
const JSON_ELF: &[u8] = include_elf!("json-program");

fn main() {
    // Set up logging for debugging and tracing.
    utils::setup_logger();

    // Initialize the proof input.
    let mut stdin = SP1Stdin::new();

    // Example JWT token (normally this would come from a real source).
    let token: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJlbWFpbCI6InRlc3RAZ21haWwuY29tIiwiYXVkIjoiNTc1NTE5MjA0MjM3LW1zb3A5ZXA0NXUydW85OGhhcHFtbmd2OGQ4NHFkYzhrLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic2FsdCI6IjY1ODg3NDE0NjkwNTA1MDI0MjE1NTAxNDAxMDUzNDUwNTA4NTkifQ.CTd77H763dYAJqsktBOBQeLK0YHYq7VQUH8E0S8vCQt6amEkUxCjb8oCaoJG_iAiWTzWan0v8treLtiOCaFtHav8vfMbE-x_hVB74LYrBa192k_oWXvlmMoyfVaRuFj9iVtKakY8PXVfMQWq9Znlus9Hg5I0CRhJpAkUTmcZTUs1TSjR_td2pPRcag46QXicafT6AvGCkLDzeMKbF7o6o5zhIUa8hd7sBrW-Ru1Uo3BdIu2KCmaE-o9xnanCB_-CB-S_reUUh692UhM_urnr3XA_s76a2jihYMMT_sbb6j25sadGN1dLbOnh05fWg-ikWYTOn0xwtqPSflWkKeVt6g";

    // RSA public key (used for verifying the JWT signature).
    let rsa_public_key = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2xKE7fuT/VV2Lk7gfCk
A4xOTcFXWboTJ6ZGx1zWCP8d1pY5mYPx/dTUgDtUjaYGIRJy6G8xYLZvj22aY3l/
DdfgLfk4Br9katexMSmKR0C9hVBWDbCk6ROK9dqEXuzGmpXhfcYs/9dL2N+Cptjs
S3PcBjxslcBJhUM60jLV+13No95DBw1f1PCEb3QNffxxVBEYLzv12xgafSjaCo+u
Y/BUgKbmU3OO6W1w+8z817t+n11mufobCHpyx5f9x7O66gEcT8YT6FtYEPSYVbxP
qXveBZaVAUe0uKlvd7yZE5ZAfyKHLNpT85ay/yfA6O4B9hwslM2El5ge3FKL53jV
FQIDAQAB
-----END PUBLIC KEY-----"#;

    // Domain we want to verify in the email.
    let domain: &str = "gmail.com";

    // Provide inputs to the proof system.
    stdin.write(&token);
    stdin.write(&rsa_public_key);
    stdin.write(&domain);

    // Initialize the prover.
    let client = ProverClient::from_env();

    // Set up the proving and verification keys.
    let (pk, vk) = client.setup(JSON_ELF);

    // Generate the proof.
    let proof = client.prove(&pk, &stdin).run().expect("proving failed");

    // Verify the proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save the proof to a file.
    proof
        .save("../../../proofs/proof_jwt_verify_email_domain.bin")
        .expect("saving proof failed");

    // Load the proof from the file to test serialization/deserialization.
    let deserialized_proof =
        SP1ProofWithPublicValues::load("../../../proofs/proof_jwt_verify_email_domain.bin")
            .expect("loading proof failed");

    // Verify the deserialized proof to ensure consistency.
    client
        .verify(&deserialized_proof, &vk)
        .expect("verification failed");

    // Print success message.
    println!("Successfully generated and verified proof for the program!");
}
