use std::time::Instant;
use std::{fs::File, path::Path};
use std::io::{self, BufRead};

use flate2::{write::ZlibEncoder, Compression};
use validate_btc_header::btc_validation::header_step::BlockHeader;
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
    CompressedSNARK, PublicParams, RecursiveSNARK,
};

type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

// Code from https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() {
    type C1 = BlockHeader<<E1 as Engine>::Scalar>;
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
    let circuit_primary: C1 = BlockHeader::default();
    let circuit_secondary: C2 = TrivialCircuit::default();

    let param_gen_timer = Instant::now();
    println!("Producing public parameters...");
    let pp = PublicParams::<E1, E2, C1, C2>::setup(
        &circuit_primary,
        &circuit_secondary,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )
    .unwrap();

    let param_gen_time = param_gen_timer.elapsed();
    println!("PublicParams::setup, took {:?} ", param_gen_time);

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );
    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    let mut input_block: [u64; 10] = [0; 10];
    let mut input2: Vec<[u64; 10]>= Vec::new();
    let mut counter_val = 0;

    let filename = "./test_blocks.txt";
    if let Ok(lines) = read_lines(filename) {
        for line in lines {
            if let Ok(edge) = line {
                counter_val = counter_val + 1;
                let items: Vec<&str> = edge.trim().split(' ').collect();
                
                let block_before_split = items[0];
                let (left1, right9) = block_before_split.split_at(16);
                let (left2, right8) = right9.split_at(16);
                let (left3, right7) = right8.split_at(16);
                let (left4, right6) = right7.split_at(16);
                let (left5, right5) = right6.split_at(16);
                let (left6, right4) = right5.split_at(16);
                let (left7, right3) = right4.split_at(16);
                let (left8, right2) = right3.split_at(16);
                let (left9, right1) = right2.split_at(16);

                input_block[0] = u64::from_str_radix(left1, 16).unwrap();
                input_block[1] = u64::from_str_radix(left2, 16).unwrap();
                input_block[2] = u64::from_str_radix(left3, 16).unwrap();
                input_block[3] = u64::from_str_radix(left4, 16).unwrap();
                input_block[4] = u64::from_str_radix(left5, 16).unwrap();
                input_block[5] = u64::from_str_radix(left6, 16).unwrap();
                input_block[6] = u64::from_str_radix(left7, 16).unwrap();
                input_block[7] = u64::from_str_radix(left8, 16).unwrap();
                input_block[8] = u64::from_str_radix(left9, 16).unwrap();
                input_block[9] = u64::from_str_radix(right1, 16).unwrap();

                input2.push(input_block);
                if counter_val == 8064 {
                    break;
                }
            }
        }
    }
    assert_eq!(input2.len(), 8064);

    // Block no. 123456-123470
    // let _input: Vec<[u64; 10]> = vec![[0x010000009500c43a, 0x25c624520b5100ad, 0xf82cb9f9da72fd24, 0x47a496bc600b0000, 0x000000006cd86237, 0x0395dedf1da2841c, 0xcda0fc489e3039de, 0x5f1ccddef0e83499, 0x1a65600ea6c8cb4d, 0xb3936a1ae3143991],
    //                                  [0x01000000cac383cd, 0xf62f68efaa8064e3, 0x5f6fc4dfc8aa7461, 0x0c6580ed17290000, 0x00000000b336398c, 0x03824f4a68c7431d, 0x0de8c2c43886ce05, 0x70840f50454049e5, 0x3ee10802c5c9cb4d, 0xb3936a1a4473abbc],
    //                                  [0x01000000666decec, 0xca2a0c7802e5de4d, 0x3e75d33473bf7070, 0x24be025f9f120000, 0x00000000d18db579, 0x621cfa0bd50971bc, 0x9932e9871f42446a, 0x6c25f138a54a57a2, 0x4f45e99ce1c9cb4d, 0xb3936a1a18d995c1],
    //                                  [0x01000000c4ec83ea, 0x9bd80edcd2bf3bf4, 0x5938101a02930140, 0x7c56dc2f033a0000, 0x00000000df1aa5bd, 0x76b592ad067b980b, 0xe9e5da8df3f9eb35, 0x205c3d39556763c0, 0x4c4b9985e6cdcb4d, 0xb3936a1a8a5a9d84],
    //                                  [0x01000000ddffde49, 0x994e39eba1735e86, 0x76447c8075362cf2, 0x7f87d8dd15660000, 0x00000000962fde96, 0x480eca46f96ac276, 0xd2dfd9f4090536b7, 0xb03bcbbcacec2a00, 0x74bd8742ded3cb4d, 0xb3936a1af55d10ad],
    //                                  [0x01000000fe664f7e, 0x27aa45dcc2cb27d3, 0x49e059ca612b7ca0, 0xcebb0dcc1e200000, 0x00000000c213a164, 0x40b6e60b26145e5b, 0x115d975cec68112f, 0xb1dc1e0495f7d805, 0x3719cba95fd4cb4d, 0xb3936a1ac0b2c58b],
    //                                  [0x0100000079b96d79, 0xba88a9b099237002, 0x04f468ccc508aaf8, 0x7fbf85ef0f2e0000, 0x00000000862035e3, 0xa60cb0175d58749a, 0xe71ff24b65f55457, 0x36fdc7d3a7d0c6c0, 0x32e08e3e88dbcb4d, 0xb3936a1aa88e7acd],
    //                                  [0x0100000059fffb58, 0x3708193c4fa6ddc1, 0xc050c7b114998d2c, 0x9d0a3d1d9e650000, 0x0000000059dafec0, 0x243f23b9fd10236d, 0x50062276471bdbcf, 0x81d6f713d12dcbc2, 0x8ecc2cea4addcb4d, 0xb3936a1a75fc4da2],
    //                                  [0x0100000029cce9d2, 0xbe1f1aab01155838, 0x66b247a27df36a27, 0x108c7701742f0000, 0x000000007340828a, 0xaedf752eb8a08965, 0xf068b484478d938e, 0xbf774ef9bea249c8, 0x07ecdfdb5fdecb4d, 0xb3936a1a73cc8c71],
    //                                  [0x01000000f9a4a51d, 0xc1ec52916f286a84, 0xd6ccdeb7e3b8a072, 0xddb071d6c00b0000, 0x0000000005316785, 0xf0e396e70f989e41, 0x01b9ea7eb421d493, 0xeec9ebe1a5d6a87e, 0xffae8c9d2ee0cb4d, 0xb3936a1a3371859e],
    //                                  [0x01000000b7f602ce, 0x3634204e6f5ffbef, 0xf94185a182652aac, 0x4f513645562d0000, 0x00000000b3cfda2a, 0x895a097beb206602, 0x705e3abeea68785a, 0xbf0be862f68bd710, 0x6b01acfca3e2cb4d, 0xb3936a1aee8f9131],
    //                                  [0x010000002c05cecd, 0xdec81d089858092d, 0xf503ceca460236f1, 0xe8d0b5194b330000, 0x00000000fc4525a2, 0x533aa1bfbe5ae7af, 0xce552c4c65b9c4e3, 0x606eb9cff71e544a, 0xb1ee9aaaeae3cb4d, 0xb3936a1ae5314f52],
    //                                  [0x01000000504e5a67, 0xf0e0236e7db07cb5, 0xea64db28825ecfaf, 0x529bcc6531430000, 0x000000007833de2f, 0x49e016ab91d5655f, 0xb2eae03f51de7df7, 0xe26b92549eda8196, 0x8fb8f3c5dbe4cb4d, 0xb3936a1a5b8ce799],
    //                                  [0x01000000bae6def8, 0x590a67694b079049, 0xe16ab9454540dd45, 0xae039c0357680000, 0x00000000016ba544, 0xffde11a8abe59e24, 0x2e1f1758ab99f9b7, 0xda37785d540dbf05, 0x81b10b0670e6cb4d, 0xb3936a1aab679d0c],
    //                                  [0x0100000049c3a56b, 0xf285778d3f919a42, 0x7ce876f71abc3e76, 0x0551fc3e57300000, 0x00000000fae9745c, 0xcfb6c4518af5773c, 0x0bb75de27c829742, 0x4b42e0cd821bed00, 0x98b11d358ce6cb4d, 0xb3936a1ab85b98a5]]; 
    let primary_circuit_sequence = C1::new_blocks(input2.clone());

    // z_0 is hash of 123455 = 0000000000000b60bc96a44724fd72daf9b92cf8ad00510b5224c6253ac40095
    let z0_primary = BlockHeader::initial_z_i_scalars();
    let z0_secondary = vec![<E2 as Engine>::Scalar::zero()];

    let proof_gen_timer = Instant::now();
    // produce a recursive SNARK
    println!("Generating a RecursiveSNARK...");
    let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> =
        RecursiveSNARK::<E1, E2, C1, C2>::new(
            &pp,
            &primary_circuit_sequence[0],
            &circuit_secondary,
            &z0_primary,
            &z0_secondary,
        )
        .unwrap();

    let start = Instant::now();
    for (i, circuit_primary) in primary_circuit_sequence.iter().enumerate() {
        let step_start = Instant::now();
        let res = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        assert!(res.is_ok());
        println!(
            "RecursiveSNARK::prove_step {}: {:?}, took {:?} ",
            i,
            res.is_ok(),
            step_start.elapsed()
        );
    }
    println!(
        "Total time taken by RecursiveSNARK::prove_steps: {:?}",
        start.elapsed()
    );

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let num_steps = primary_circuit_sequence.len();
    let res = recursive_snark.verify(&pp, num_steps, &z0_primary, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();

    let start = Instant::now();

    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let proving_time = proof_gen_timer.elapsed();
    println!("Total proving time is {:?}", proving_time);

    let compressed_snark = res.unwrap();

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
    let compressed_snark_encoded = encoder.finish().unwrap();
    println!(
        "CompressedSNARK::len {:?} bytes",
        compressed_snark_encoded.len()
    );

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(&vk, num_steps, &z0_primary, &z0_secondary);
    let verification_time = start.elapsed();
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        verification_time,
    );
    assert!(res.is_ok());
    println!("=========================================================");
    println!("Public parameters generation time: {:?} ", param_gen_time);
    println!(
        "Total proving time (excl pp generation): {:?}",
        proving_time
    );
    println!("Total verification time: {:?}", verification_time);

    println!("=========================================================");
}
