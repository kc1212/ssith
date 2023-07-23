use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use ssith::*;

fn main() {
    let param = Param::default();
    let mut rng = ChaChaRng::from_entropy();
    let prover = Prover::new(&mut rng, param);
    let step1_state = prover.step1();
    println!("{}", serde_json::to_string(&step1_state).unwrap());
}
