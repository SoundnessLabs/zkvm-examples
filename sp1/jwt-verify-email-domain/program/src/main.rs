#![no_main]
sp1_zkvm::entrypoint!(main);

use lib::{split_email, split_jwt, pem_to_der};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha2_v0_10_8::{Digest, Sha256};

pub fn main() {
    // Read input values: JWT token, RSA public key, and the expected domain
    let token = sp1_zkvm::io::read::<String>();
    let rsa_public_key = sp1_zkvm::io::read::<String>();
    let domain = sp1_zkvm::io::read::<String>();

    // Commit the domain to the zk proof (so it’s publicly known)
    sp1_zkvm::io::commit(&domain);

    // Split the JWT into its components: header, payload, and signature
    let (header, payload, signature) = split_jwt(&token)
        .expect("Failed to decode JWT"); // Panic if JWT parsing fails
    
    // Convert the PEM public key into DER format for RSA verification
    let pk_der = pem_to_der(&rsa_public_key);
    let public_key = RsaPublicKey::from_public_key_der(&pk_der).unwrap();

    // Reconstruct the signing input (header + payload) as a string
    let signing_input = format!(
        "{}.{}",
        token.split('.').collect::<Vec<&str>>()[0], // First part: header
        token.split('.').collect::<Vec<&str>>()[1]  // Second part: payload
    );

    // Hash the signing input using SHA256
    let mut hasher = Sha256::new();
    hasher.update(signing_input);
    let hashed_msg = hasher.finalize();

    // Verify the JWT signature using the provided RSA public key
    let verification_result = match public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_msg, &signature) {
        Ok(_) => true,  // Signature is valid
        Err(_) => false, // Signature is invalid
    };

    // Commit the verification result (proof that the JWT is authentic)
    sp1_zkvm::io::commit(&verification_result);

    // Extract and split the email address from the JWT payload
    let email_parts = split_email(payload.get("email").unwrap().to_string()).unwrap();

    // Check if the email domain matches the expected domain
    let verified = email_parts.domain == domain;

    // Commit the verification result (proof that the email domain is correct)
    sp1_zkvm::io::commit(&verified);
}
