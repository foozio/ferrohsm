use ml_dsa::{
    KeyGen, MlDsa44, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::thread_rng;

fn main() {
    let msg = b"Hello, ML-DSA!";

    // Generate a keypair
    let mut rng = thread_rng();
    let kp = MlDsa44::key_gen(&mut rng);
    let signing_key = kp.signing_key();
    let verifying_key = kp.verifying_key();

    // Sign the message and verify the signature
    let signature = signing_key.sign(msg);
    verifying_key.verify(msg, &signature).expect("verify");

    // Encode keys to their byte representation
    let encoded_signing = signing_key.encode();
    let encoded_verifying = verifying_key.encode();

    // Recreate keys from their encoded form and repeat the round-trip
    let signing_key2 = SigningKey::<MlDsa44>::decode(&encoded_signing);
    let verifying_key2 = VerifyingKey::<MlDsa44>::decode(&encoded_verifying);

    let signature2 = signing_key2.sign(msg);
    verifying_key2.verify(msg, &signature2).expect("verify");

    println!("ML-DSA signing round-trip succeeded!");
}
