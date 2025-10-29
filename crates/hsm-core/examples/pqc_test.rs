use ml_dsa::{
    signature::{Keypair, Signer, Verifier},
    KeyGen, MlDsa44,
};
use pkcs8::{der::Decode, PrivateKeyInfo, SubjectPublicKeyInfo};
use rand::thread_rng;

fn main() {
    let msg = b"Hello, ML-DSA!";

    // Generate a keypair
    let mut rng = thread_rng();
    let kp = MlDsa44::key_gen(&mut rng);
    let signing_key = kp.signing_key();
    let verifying_key = kp.verifying_key();

    // Sign the message
    let signature = signing_key.sign(msg);

    // Verify the signature
    assert!(verifying_key.verify(msg, &signature).is_ok());

    // Now, let's try to do the same with raw bytes
    let private_key_bytes = signing_key.to_pkcs8_der().unwrap();
    let public_key_bytes = verifying_key.to_public_key_der().unwrap();

    // Create a signing key from raw bytes
    let pki = PrivateKeyInfo::from_der(&private_key_bytes).unwrap();
    let signing_key2 = ml_dsa::SigningKey::<MlDsa44>::try_from(pki).unwrap();

    // Create a verifying key from raw bytes
    let spki = SubjectPublicKeyInfo::from_der(&public_key_bytes).unwrap();
    let verifying_key2 = ml_dsa::VerifyingKey::<MlDsa44>::try_from(spki).unwrap();

    // Sign and verify again
    let signature2 = signing_key2.sign(msg);
    assert!(verifying_key2.verify(msg, &signature2).is_ok());

    println!("All tests passed!");
}
