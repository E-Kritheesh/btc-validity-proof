use std::marker::PhantomData;

use crate::btc_validation::{difficulty_update, median};

use bellpepper_core::{
    boolean,
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use bellpepper::gadgets::sha256;
use bellpepper_nonnative::mp::bignat::BigNat;
use bellpepper_nonnative::util::convert::{f_to_nat, nat_to_f};
// use bellpepper::gadgets::num::{AllocatedNum, Num};
use nova_snark::traits::circuit::StepCircuit;

#[derive(Clone, Debug)]
pub struct BlockHeader <F>
where
    F: PrimeField,
{
    block_head: [u64; 10],
    marker: PhantomData<F>,
}

impl<F> Default for BlockHeader <F>
where
    F: PrimeField + PrimeFieldBits,
{
    fn default() -> Self {
        Self {
            block_head: [0u64; 10],
            marker: Default::default(),
        }
    }
}


impl<F> BlockHeader<F>
where
    F: PrimeField + PrimeFieldBits,
{
    // Produces the intermediate blocks when a message is hashed
    pub fn new_blocks(input: Vec<[u64;10]>) -> Vec<Self> {
        // let block_seq = sha256_msg_block_sequence(input);
        input
            .into_iter()
            .map(|b| BlockHeader {
                block_head: b,
                marker: PhantomData,
            })
            .collect()
    }


    // pub fn initial_z_i_scalars() -> Vec<F>
    // {
    //     let mut initial_z = Vec::new();

    //     // let n = 0x0000000000000b60bc96a44724fd72daf9b92cf8ad00510b5224c6253ac40095;
    //     let curr_hash = F::from_str_vartime("18283544428642297129396529020735695233361821945456783020785813").unwrap();
    //     initial_z.push(curr_hash);

    //     // previous 11 timestamps
    //     let t1 = F::from_str_vartime("1305191152").unwrap(); //123445
    //     initial_z.push(t1);
        
    //     let t2 = F::from_str_vartime("1305191688").unwrap(); //123446
    //     initial_z.push(t2);
        
    //     let t3 = F::from_str_vartime("1305193319").unwrap(); //123447
    //     initial_z.push(t3);
        
    //     let t4 = F::from_str_vartime("1305194571").unwrap(); //123448
    //     initial_z.push(t4);
        
    //     let t5 = F::from_str_vartime("1305194986").unwrap(); //123449
    //     initial_z.push(t5);
        
    //     let t6 = F::from_str_vartime("1305195947").unwrap(); //123450
    //     initial_z.push(t6);
        
    //     let t7 = F::from_str_vartime("1305197900").unwrap(); //123451
    //     initial_z.push(t7);
        
    //     let t8 = F::from_str_vartime("1305199436").unwrap(); //123452
    //     initial_z.push(t8);
        
    //     let t9 = F::from_str_vartime("1305200301").unwrap(); //123453
    //     initial_z.push(t9);
        
    //     let t10 = F::from_str_vartime("1305200460").unwrap(); //123454
    //     initial_z.push(t10);
        
    //     let t11 = F::from_str_vartime("1305200584").unwrap(); //123455
    //     initial_z.push(t11);

    //     let target = F::from_str_vartime("171262555713783851185422181139260521316022447660158187451973632").unwrap();
    //     initial_z.push(target);

    //     let start_time_epoch = F::from(1304975844u64);
    //     initial_z.push(start_time_epoch);

    //     let counter = F::from(480u64);
    //     initial_z.push(counter);

    //     let chain_work = F::ZERO;
    //     initial_z.push(chain_work);

    //     initial_z
    // }

    pub fn initial_z_i_scalars() -> Vec<F>
    {
        let mut initial_z = Vec::new();

        // let n = 0x00000000000000000015a08d0a60237487070fe0d956d5fb5fd9d21ad6d7b2d3;
        let curr_hash = F::from_str_vartime("2071469635416284396978377184346583930482353518346220243").unwrap();
        initial_z.push(curr_hash);

        // previous 11 timestamps
        let t1 = F::from_str_vartime("1545170929").unwrap(); //554389
        initial_z.push(t1);
        
        let t2 = F::from_str_vartime("1545171245").unwrap(); //554390
        initial_z.push(t2);
        
        let t3 = F::from_str_vartime("1545171316").unwrap(); //554391
        initial_z.push(t3);
        
        let t4 = F::from_str_vartime("1545171411").unwrap(); //554392
        initial_z.push(t4);
        
        let t5 = F::from_str_vartime("1545172119").unwrap(); //554393
        initial_z.push(t5);
        
        let t6 = F::from_str_vartime("1545172682").unwrap(); //554394
        initial_z.push(t6);
        
        let t7 = F::from_str_vartime("1545174730").unwrap(); //554395
        initial_z.push(t7);
        
        let t8 = F::from_str_vartime("1545174899").unwrap(); //554396
        initial_z.push(t8);
        
        let t9 = F::from_str_vartime("1545174978").unwrap(); //554397
        initial_z.push(t9);
        
        let t10 = F::from_str_vartime("1545175153").unwrap(); //554398
        initial_z.push(t10);
        
        let t11 = F::from_str_vartime("1545175878").unwrap(); //554399
        initial_z.push(t11);

        // prev target = 0x00000000000000000031d97c0000000000000000000000000000000000000000;
        let target = F::from_str_vartime("4774638159061819979596346127394133648234752261950013440").unwrap();
        initial_z.push(target);

        let start_time_epoch = F::from(1337510);
        initial_z.push(start_time_epoch);

        let counter = F::from(0u64);
        initial_z.push(counter);

        let chain_work = F::from(0u64);
        initial_z.push(chain_work);

        initial_z
    }
}

impl<F> StepCircuit<F> for BlockHeader <F>
where
    F: PrimeField + PrimeFieldBits,
{   
    fn arity(&self) -> usize {
        16
    }

    fn synthesize<CS: ConstraintSystem <F> >(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let header = self.block_head.to_vec();
        let z_i = (*z).to_vec();
        
        // println!("{}", header[0]);
        // println!("{}", header[1]);
        // println!("{}",header[2]);
        // println!("{}", header[3]);
        // let hash_s = z_i[1].get_value().unwrap();
        // let (_s1000, hash32) = f_to_nat(&hash_s).to_u32_digits();
        // for (_i, h) in hash32.iter().enumerate() {
        //     println!("{}", *h);
        // }
        

        // 1. Check if prevHash from z and prev_hash_from_curr_block are equal 
        //
        // Taking the example of block no. 123456
        // 0x010000009500c43a 25c624520b5100ad f82cb9f9da72fd24 47a496bc600b0000 000000006cd86237 0395dedf1da2841c cda0fc489e3039de 5f1ccddef0e83499 1a65600ea6c8cb4d b3936a1ae3143991
        // here 0x9500c43a25c624520b5100adf82cb9f9da72fd2447a496bc600b000000000000 is the prevhash (0000000000000b60bc96a44724fd72daf9b92cf8ad00510b5224c6253ac40095)

        let mut prev_hash_from_curr_block_vec: Vec<u64> = Vec::new();
        for i in 0..4 {
            let hash_vec = (header[i] % (1 << 32 as u64)) * (1<<32 as u64) + header[i+1] / (1 << 32 as u64);
            prev_hash_from_curr_block_vec.push(hash_vec);
        }

        let mut prev_hash_from_curr_block: Vec<boolean::Boolean> = Vec::new();
        for (i, hash64) in prev_hash_from_curr_block_vec.iter().enumerate() {
            let mut dummy = boolean::u64_into_boolean_vec_le(cs.namespace(|| format!("dummy {}", i)), Some(*hash64)).unwrap();
            dummy.reverse();
            prev_hash_from_curr_block.append(&mut dummy);
        }

        let prev_hash = AllocatedNum::alloc(cs.namespace(|| {"last block hash"}), || {
            let mut sum: F = F::ZERO;

            for (i, b) in prev_hash_from_curr_block.iter().enumerate() {
                let exponent = 16 * (i/8) + 7 - i;
                if exponent >= 128 {
                    let power_127 = F::from_u128(1 << 127);
                    let mut power_2 = if (*b).get_value().unwrap() { F::from_u128(1 << (exponent - 127)) }  else { F::from_u128(0u128) };
                    power_2.mul_assign(&power_127);
                    sum.add_assign(&power_2);
                }
                else {
                    let power_2 = if (*b).get_value().unwrap() { F::from_u128(1 << exponent) } else { F::from_u128(0u128) };
                    sum.add_assign(&power_2);
                } 
            }

            Ok(sum)
        }).unwrap();

        // equality check
        let r_prev_hash = BigNat::equals(cs.namespace(|| {"Is prev. hash from current block equal to the last block hash?"}), &z_i[0], &prev_hash).unwrap();
        assert!(r_prev_hash.get_value().or(Some(true)).unwrap());
        
        // 2. Check if current hash <= target
        //
        // Target computation from threshold
        // Taking the example of block no. 123456
        // 0x010000009500c43a 25c624520b5100ad f82cb9f9da72fd24 47a496bc600b0000 000000006cd86237 0395dedf1da2841c cda0fc489e3039de 5f1ccddef0e83499 1a65600ea6c8cb4d b3936a1ae3143991
        // here 0x1a6a93b3 is the threshold
        let n_bits = (header[9] >> 32) as u32; // nbits = b3936a1a
        let b0 = (n_bits % 256u32) as u8; // 1a
        let b3 = (n_bits >> 24) as u8;    // b3
        let b2 = ((n_bits >> 16) - ((b3 as u32) << 8)) as u8; // n_bits >> 16 = b393; b3 << 8 = b300; => b2 = 93
        let b1 = ((n_bits >> 8) - ((b3 as u32) << 16) - ((b2 as u32) << 8)) as u8; // n_bits >> 8 = b3936a; b3 << 16 = b30000; b2 << 8 = 9300; => b1 = 6a

        // println!("n_bits {}", n_bits); // B3936A1A
        // println!("b0 {}", b0); // 1A
        // println!("b1 {}", b1); // 6A
        // println!("b2 {}", b2); // 93
        // println!("b3 {}", b3); // B3
        
        let target = AllocatedNum::alloc(cs.namespace(|| "Block target"), || {
            let thresh_mantissa = ((b1 as u32) << 16 )+ ((b2 as u32) << 8) + (b3 as u32);
            let exponent = (b0 - 3) as usize;

            let targ: F = if exponent >= 13 {
                let partial_scalar = F::from_u128((thresh_mantissa as u128) << (8 * 13) as u128);
                let mut scale = F::from_u128(1 << (8 * (exponent - 13)) as u128);
                scale.mul_assign(&partial_scalar);

                scale
            }
            else {
                F::from_u128((thresh_mantissa as u128) << 8 * exponent) 
            };

            Ok(targ)
        }).unwrap();

        // Current block hash computation
        let mut preimage_vec: Vec<boolean::Boolean> = Vec::new();
        for (i, preimage64) in header.iter().enumerate() {
            let mut dummy2 = boolean::u64_into_boolean_vec_le(cs.namespace(|| format!("dummy2 {}", i)), Some(*preimage64)).unwrap();
            dummy2.reverse();
            preimage_vec.append(&mut dummy2);
        }

        let out_sha256 = sha256::sha256(cs.namespace(|| "SHA 256"), &preimage_vec).unwrap();
        let out = sha256::sha256(cs.namespace(|| "SHA 256d"), &out_sha256).unwrap();
        
        let curr_hash = AllocatedNum::alloc(cs.namespace(|| {"current block hash"}), || {
            let mut sum: F = F::ZERO;

            for (i, b) in out.iter().enumerate() {
                let exponent = 16 * (i/8) + 7 - i;
                if exponent >= 128 {
                    let power_127 = F::from_u128(1 << 127);
                    let mut power_2 = if (*b).get_value().unwrap() { F::from_u128(1 << (exponent - 127)) }  else { F::from_u128(0u128) };
                    power_2.mul_assign(&power_127);
                    sum.add_assign(&power_2);
                }
                else {
                    let power_2 = if (*b).get_value().unwrap() { F::from_u128(1 << exponent) } else { F::from_u128(0u128) };
                    sum.add_assign(&power_2);
                } 
            }

            Ok(sum)
        }).unwrap();

        // less than check
        let r_curr_hash_targ = median::less_than(cs.namespace(|| "Is PoW consensus achieved?"), &curr_hash, &target, 250usize)?;
        assert!(r_curr_hash_targ.get_value().or(Some(true)).unwrap());

        // let current_hashed = curr_hash.get_value().or(Some(F::ONE)).unwrap();
        // let tar_tar = target.get_value().or(Some(F::ONE)).unwrap();

        // let (_star, time_tar) = f_to_nat(&tar_tar).to_u32_digits();
        // for (_i, htar) in time_tar.iter().enumerate() {
        //     println!("Target = {}", *htar);
        // }

        // let (_shas, time_has) = f_to_nat(&current_hashed).to_u32_digits();
        // for (_i, hhas) in time_has.iter().enumerate() {
        //     println!("Hash = {}", *hhas);
        // }

        // assert!(r_curr_hash_targ.get_value().or(Some(true)).unwrap()); NEED TO BE FIXED!!!

        // 3. Check if timestamp of the current block is greater than the median of previous 11 timestamps
        //
        let mut times_vec: Vec<u32> = Vec::new(); 
        for i in 1..=11 {
            let timestamp = z_i[i].get_value().or(Some(F::ONE)).unwrap();
            let (_s, time32) = f_to_nat(&timestamp).to_u32_digits();
            times_vec.push(time32[0]);
        }

        // compute median
        let median = median::compute_median_timestamp(&mut times_vec);

        // verify median
        let r_median = median::verify_median_timestamp(cs.namespace(|| "median verify"), &mut times_vec, median).unwrap();
        assert!(r_median.get_value().or(Some(true)).unwrap());

        // check if median < current timestamp
        // Taking the example of block no. 123456
        // 0x010000009500c43a 25c624520b5100ad f82cb9f9da72fd24 47a496bc600b0000 000000006cd86237 0395dedf1da2841c cda0fc489e3039de 5f1ccddef0e83499 1a65600ea6c8cb4d b3936a1ae3143991
        // here 0xa6c8cb4d is the current timestamp (supposed to be 0x4dcbc8a6)
        let n_time = (header[8] % (1 << 32)) as u32; // 0xa6c8cb4d
        let b_t0 = (n_time % 256u32) as u8; // 4d
        let b_t3 = (n_time >> 24) as u8;  // a6
        let b_t2 = ((n_time >> 16) - ((b_t3 as u32) << 8)) as u8; // n_time >> 16 = a6c8; b_t3 << 8 = a600 ; => b_t2 = c8
        let b_t1 = ((n_time >> 8) - ((b_t3 as u32) << 16) - ((b_t2 as u32) << 8)) as u8; // n_time >> 8 = a6c8cb; b_t3 << 16 = a60000; b_t2 << 8 = c800; => b_t1 = cb
        let n_time_endian = ((b_t0 as u32) << 24) + ((b_t1 as u32) << 16) + ((b_t2 as u32) << 8) + (b_t3 as u32);

        // println!("n_time {}", n_time); // A6C8CB4D
        // println!("b_t0 {}", b_t0); // 4D
        // println!("b_t1 {}", b_t1); // CB
        // println!("b_t2 {}", b_t2); // C8
        // println!("b_t3 {}", b_t3); // A6
        // println!("n_time_endian {}", n_time_endian); // 4DCBC8A6

        let median_fe = AllocatedNum::alloc(cs.namespace(|| "median"), || Ok(F::from(median as u64))).unwrap();
        let curr_timestamp = AllocatedNum::alloc(cs.namespace(|| "current timestamp"), || Ok(F::from(n_time_endian as u64))).unwrap();
        let r_time = median::less_than(cs.namespace(|| "valid timestamp"), &median_fe, &curr_timestamp, 32usize).unwrap();
        assert!(r_time.get_value().or(Some(true)).unwrap());

        // 4. Total work addition
        //
        let max_target = AllocatedNum::alloc(cs.namespace(|| "maximum target"), || {
            let power_127 = F::from_u128(1 << 127);
            let mut max_thresh = F::from_u128(0xFFFF << 81);
            max_thresh.mul_assign(&power_127);

            Ok(max_thresh)
        }).unwrap();

        let block_work = AllocatedNum::alloc(cs.namespace(|| "work or difficulty"), || {
            let diff = max_target.get_value().unwrap();
            let targ = target.get_value().unwrap();

            let diff_big = f_to_nat(&diff);
            let tar_big = f_to_nat(&targ);
            let work = diff_big / tar_big;

            let work_scalar = nat_to_f(&work).unwrap();
            Ok(work_scalar)
        }).unwrap();

        let work_remainder = AllocatedNum::alloc(cs.namespace(|| "work remainder"), || {
            let diff = max_target.get_value().unwrap();
            let targ = target.get_value().unwrap();

            let diff_big = f_to_nat(&diff);
            let tar_big = f_to_nat(&targ);
            let work = diff_big / tar_big;

            let targ_block = f_to_nat(&targ);
            let multiple_work = work * targ_block;

            let remainder = f_to_nat(&diff) - multiple_work;
            let rem_scalar = nat_to_f(&remainder).unwrap();

            Ok(rem_scalar)
        }).unwrap();

        // Constrain allocation:
        // max_target = target * block_work
        cs.enforce(
            || "max_target = target * block_work",
            |lc| lc + target.get_variable(),
            |lc| lc + block_work.get_variable(),
            |lc| lc + max_target.get_variable() - work_remainder.get_variable(),
        );

        let res_tar_rem = median::less_than(cs.namespace(|| "Is remainder less than divisor?"), &work_remainder, &target, 250usize)?;
        assert!(res_tar_rem.get_value().or(Some(true)).unwrap());

        // 5. Target update
        //
        // Either the counter i.e. z_i[14] == 0 or target from z_i is equal to curr_target
        // The counter z_i[14] has value r for (2016q + r)th block

        // Constrain allocation:
        // 0 = (target - z_i[12]) * z_i[14]
        cs.enforce(
            || "0 = (target - z_i[12]) * z_i[14]",
            |lc| lc + target.get_variable() - z_i[12].get_variable(),
            |lc| lc + z_i[14].get_variable(),
            |lc| lc,
        );

        // let start_time_epoch = z_i[13].clone();
        let start_time_epoch = AllocatedNum::alloc(cs.namespace(|| "start time of 2016 block epoch"), || {
            let start_time = z_i[13].get_value().unwrap();
            let mut counter_delta = z_i[14].get_value().unwrap();
            let const_2015 = F::from(2015u64);
            counter_delta.sub_assign(&const_2015);

            if counter_delta.is_zero().unwrap_u8() == 1 {
                let curr_time = curr_timestamp.get_value().unwrap();
                Ok(curr_time - start_time) // we have to return curr_timestamp - start_time here
            } else if z_i[14].get_value().unwrap().is_zero().unwrap_u8() == 1 {
                Ok(curr_timestamp.get_value().unwrap())
            } else {
                Ok(start_time)
            }
        })?;

        let target_calc = difficulty_update::calculate_difficulty_update(cs.namespace(|| "target calculated"), &z_i[12], &z_i[13]).unwrap();
        let mut bigint_tar = target_calc.value.unwrap_or_default();
        let exponent = 8 * (b0 - 3) as usize;
        bigint_tar = bigint_tar >> exponent;
        bigint_tar = bigint_tar << exponent; 

        // let (_s2_calc, target_u64_calc) = bigint_tar.to_u64_digits();
        // // if target_u64_calc.len() > 0 {
        // //     let trunc_next_tar_lsb = ((target_u64_calc[0] as u128) + ((target_u64_calc[1] as u128) << 64)) >> (8 * (b0 - 3));
        // //     println!("truncated next target {}", trunc_next_tar_lsb);
        // // }

        let calculated_target = AllocatedNum::alloc(cs.namespace(|| "target updated"), || {
            let cal_tar_scalar = nat_to_f(&bigint_tar).unwrap();
            Ok(cal_tar_scalar)
        }).unwrap();

        // let _r = BigNat::equals(cs.namespace(|| "verify target update"), &target, &calculated_target).unwrap();
        
        // Either the counter z_i[14] is non-zero or curr_target = calc_target = z_i[12] * t_sum / (2016*10*60)
        let delta_inv = AllocatedNum::alloc(cs.namespace(|| "delta_inv"), || {
            let delta = z_i[14].get_value().unwrap();

            if delta.is_zero().unwrap_u8() == 1 {
                Ok(F::ONE) // we can return any number here, it doesn't matter
            } else {
                Ok(delta.invert().unwrap())
            }
        })?;

        // Allocate `t = z_i[14] * delta_inv`
        // If `z_i[14]` is non-zero, `t` will equal 1
        // If `z_i[14]` is zero, `t` will equal 0

        let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
            let mut tmp = z_i[14].get_value().unwrap();
            tmp.mul_assign(&(delta_inv.get_value().unwrap()));

            Ok(tmp)
        })?;

        // Constrain allocation:
        // t = z_i[14] * delta_inv
        cs.enforce(
            || "t = z_i[14] * delta_inv",
            |lc| lc + z_i[14].get_variable(),
            |lc| lc + delta_inv.get_variable(),
            |lc| lc + t.get_variable(),
        );

        // Constrain:
        // z_i[14] * (t - 1) == 0
        // This enforces that correct `delta_inv` was provided,
        // and thus `t` is 1 if `z_i[14]` is non zero
        cs.enforce(
            || "z_i[14] * (t - 1) == 0",
            |lc| lc + z_i[14].get_variable(),
            |lc| lc + t.get_variable() - CS::one(),
            |lc| lc,
        );

        // Constrain:
        // (curr_target - calc_target) * (t - 1) == 0
        // This enforces that correct `delta_inv` was provided,
        // and thus `t` is 1 if `z_i[14]` is non zero
        cs.enforce(
            || "(curr_target - calc_target) * (t - 1) == 0",
            |lc| lc + target.get_variable() - calculated_target.get_variable(),
            |lc| lc + t.get_variable() - CS::one(),
            |lc| lc,
        );

        // let t_felt = t.get_value().or(Some(F::ONE)).unwrap();
        // let t_nat = f_to_nat(&t_felt);
        // let (_t, tfelt_32) = t_nat.to_u32_digits();
        
        // assert_eq!(tfelt_32[0], 1u32);
        
        // Either the counter z_i[14] is not equal to 2015 or start_time_epoch = z_i[13]


        // 6. z_out
        //
        // If the counter i.e z_i[14] == 2015, then z_out[14] = 0. Else, z_out[14] = z_i[14] + 1.
        let mut z_out: Vec<AllocatedNum<F>> = Vec::new();
        z_out.push(curr_hash.clone()); // z_out[0]
        cs.enforce(
            || "current SHA256d hash out", 
            |lc| lc,
            |lc| lc,
            |lc| lc + z_out[0].get_variable() - curr_hash.get_variable(),
        );

        
        for i in 1..=10 {
            z_out.push(z_i[i+1].clone()); // z_out[1..=10]

            cs.enforce(
                || format!("timestamp out {}", i), 
                |lc| lc,
                |lc| lc,
                |lc| lc + z_out[i].get_variable() - z_i[i + 1].get_variable(),
            );
        }

        z_out.push(curr_timestamp.clone()); // z_out[11]
        cs.enforce(
            || "current timestamp out", 
            |lc| lc,
            |lc| lc,
            |lc| lc + z_out[11].get_variable() - curr_timestamp.get_variable(),
        );

        z_out.push(target.clone()); // z_out[12]
        cs.enforce(
            || "current target out", 
            |lc| lc,
            |lc| lc,
            |lc| lc + z_out[12].get_variable() - target.get_variable(),
        );

        z_out.push(start_time_epoch.clone()); // z_out[13]
        cs.enforce(
            || "current start time epoch out", 
            |lc| lc,
            |lc| lc,
            |lc| lc + z_out[13].get_variable() - start_time_epoch.get_variable(),
        );

        // z_out[14]
        z_out.push(AllocatedNum::alloc(cs.namespace(|| "target counter"), || {
            let mut prev_ctr = z_i[14].get_value().unwrap();

            prev_ctr.add_assign(F::ONE);

            let mut const_2016 = F::from(2016u64);
            const_2016.sub_assign(&prev_ctr);

            if const_2016.is_zero().unwrap_u8() == 1 {
                prev_ctr = F::ZERO;
            }

            Ok(prev_ctr)
        }).unwrap());

        let zero_flag = AllocatedNum::alloc(cs.namespace(|| "counter zero flag"), || {
            let mut prev_ctr = z_i[14].get_value().unwrap();
            let mut flag = F::ZERO;

            prev_ctr.add_assign(F::ONE);

            let mut const_2016 = F::from(2016u64);
            const_2016.sub_assign(&prev_ctr);

            if const_2016.is_zero().unwrap_u8() == 1 {
                flag = F::ONE;
            }

            Ok(flag)
        }).unwrap();

        cs.enforce(
            || "z_out[14] = (z_i[14] + 1)*(1-zero_flag)", 
            |lc| lc + CS::one() + z_i[14].get_variable(),
            |lc| lc + CS::one() - zero_flag.get_variable(),
            |lc| lc + z_out[14].get_variable(),
        );

        // total work
        // z_out[15]
        z_out.push(AllocatedNum::alloc(cs.namespace(|| "total work"), || {
            let prev_total = z_i[15].get_value().unwrap();
            let mut curr_work = block_work.get_value().unwrap();

            curr_work.add_assign(&prev_total);
            Ok(curr_work)
        }).unwrap());

        cs.enforce(
            || "z_out[15] = z_i[15] + block_work", 
            |lc| lc + block_work.get_variable() + z_i[15].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z_out[15].get_variable(),
        );

        Ok(z_out)
    }
}


#[cfg(test)]
mod tests {
    use bellpepper_core::test_cs::TestConstraintSystem;
    use pasta_curves::Fp;
    use super::*;

    #[test]
    fn test_synthesize_for_no_2016k() {
        let mut cs = TestConstraintSystem::<Fp>::new();

        let input: Vec<[u64; 10]>= vec![[0x010000009500c43a, 0x25c624520b5100ad, 0xf82cb9f9da72fd24, 0x47a496bc600b0000, 0x000000006cd86237, 0x0395dedf1da2841c, 0xcda0fc489e3039de, 0x5f1ccddef0e83499, 0x1a65600ea6c8cb4d, 0xb3936a1ae3143991]];
        let mut one_block_vec:Vec<BlockHeader<Fp>> = BlockHeader::new_blocks(input);
        assert_eq!(one_block_vec.len(), 1);

        let block_123456 = one_block_vec.pop().unwrap();
        let mut z_in: Vec<AllocatedNum<Fp>> = vec![];

        for (i, s) in BlockHeader::initial_z_i_scalars().iter().enumerate() {
            z_in.push(
                AllocatedNum::alloc(cs.namespace(|| format!("z_in[{i}]")), || Ok(*s)).unwrap(),
            );
        }
        let z_out = block_123456.synthesize(&mut cs, &z_in).unwrap();
        assert_eq!(z_out.len(), 16);

        if let Some(token) = cs.which_is_unsatisfied() {
            eprintln!("Error: {} is unsatisfied", token);
        }

        assert!(cs.is_satisfied());

        let correct_start_t = AllocatedNum::alloc(cs.namespace(|| "correct start time"), || Ok(Fp::from(1304975844u64))).unwrap(); 
        let r = BigNat::equals(cs.namespace(|| {"equality check"}), &z_out[13], &correct_start_t).unwrap();
        assert!(r.get_value().unwrap());
    }

    #[test]
    fn test_synthesize_for_2016_275() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        
        // block 554400
        let input: Vec<[u64; 10]>= vec![[0x00004020d3b2d7d6, 0x1ad2d95ffbd556d9, 0xe00f07877423600a, 0x8da0150000000000, 0x00000000d192743a, 0x2c190a7421f92fef, 0xe92505579d7b8eda, 0x568cacee13b25751, 0xac704c669d83195c, 0xf41e371721bae3e7]];
        let mut one_block_vec:Vec<BlockHeader<Fp>> = BlockHeader::new_blocks(input);
        assert_eq!(one_block_vec.len(), 1);

        let block_554400 = one_block_vec.pop().unwrap();
        let mut z_in: Vec<AllocatedNum<Fp>> = vec![];

        let mut initial_z = Vec::new();

        // let n = 0x00000000000000000015a08d0a60237487070fe0d956d5fb5fd9d21ad6d7b2d3;
        let curr_hash = Fp::from_str_vartime("2071469635416284396978377184346583930482353518346220243").unwrap();
        initial_z.push(curr_hash);

        // previous 11 timestamps
        let t1 = Fp::from_str_vartime("1545170929").unwrap(); //554389
        initial_z.push(t1);
        
        let t2 = Fp::from_str_vartime("1545171245").unwrap(); //554390
        initial_z.push(t2);
        
        let t3 = Fp::from_str_vartime("1545171316").unwrap(); //554391
        initial_z.push(t3);
        
        let t4 = Fp::from_str_vartime("1545171411").unwrap(); //554392
        initial_z.push(t4);
        
        let t5 = Fp::from_str_vartime("1545172119").unwrap(); //554393
        initial_z.push(t5);
        
        let t6 = Fp::from_str_vartime("1545172682").unwrap(); //554394
        initial_z.push(t6);
        
        let t7 = Fp::from_str_vartime("1545174730").unwrap(); //554395
        initial_z.push(t7);
        
        let t8 = Fp::from_str_vartime("1545174899").unwrap(); //554396
        initial_z.push(t8);
        
        let t9 = Fp::from_str_vartime("1545174978").unwrap(); //554397
        initial_z.push(t9);
        
        let t10 = Fp::from_str_vartime("1545175153").unwrap(); //554398
        initial_z.push(t10);
        
        let t11 = Fp::from_str_vartime("1545175878").unwrap(); //554399
        initial_z.push(t11);

        // prev target = 0x00000000000000000031d97c0000000000000000000000000000000000000000;
        let target = Fp::from_str_vartime("4774638159061819979596346127394133648234752261950013440").unwrap();
        initial_z.push(target);

        let start_time_epoch = Fp::from(1337510);
        initial_z.push(start_time_epoch);

        let counter = Fp::from(0u64);
        initial_z.push(counter);

        let chain_work = Fp::from(0u64);
        initial_z.push(chain_work);

        for (i, s) in initial_z.iter().enumerate() {
            z_in.push(
                AllocatedNum::alloc(cs.namespace(|| format!("z_in[{i}]")), || Ok(*s)).unwrap(),
            );
        }
        let z_out = block_554400.synthesize(&mut cs, &z_in).unwrap();
        assert_eq!(z_out.len(), 16);

        if let Some(token) = cs.which_is_unsatisfied() {
            eprintln!("Error: {} is unsatisfied", token);
        }

        assert!(cs.is_satisfied());

        let correct_start_t = AllocatedNum::alloc(cs.namespace(|| "correct start time"), || Ok(Fp::from(1545175965u64))).unwrap(); 
        let r = BigNat::equals(cs.namespace(|| {"equality check"}), &z_out[13], &correct_start_t).unwrap();
        assert!(r.get_value().unwrap());
    }

    #[test]
    fn test_synthesize_for_554399() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        
        // block 554399
        let input: Vec<[u64; 10]>= vec![[0x000000202da0c39c, 0x117f882d54d03df8, 0x22915a8a6373be4c, 0xfa1a010000000000, 0x00000000dd6f24bd, 0x263432435f0954c5, 0x9c022cfd8e5190f4, 0x615fc2c249815244, 0xa3fe09b34683195c, 0x7cd931170f68c64a]];
        let mut one_block_vec:Vec<BlockHeader<Fp>> = BlockHeader::new_blocks(input);
        assert_eq!(one_block_vec.len(), 1);

        let block_554399 = one_block_vec.pop().unwrap();
        let mut z_in: Vec<AllocatedNum<Fp>> = vec![];

        let mut initial_z = Vec::new();

        // let n = 0x000000000000000000011afa4cbe73638a5a9122f83dd0542d887f119cc3a02d;
        let curr_hash = Fp::from_str_vartime("105874539742017224273325032098189421706642276586070061").unwrap();
        initial_z.push(curr_hash);

        // previous 11 timestamps
        let t11 = Fp::from_str_vartime("1545170622").unwrap(); //554388
        initial_z.push(t11);

        let t1 = Fp::from_str_vartime("1545170929").unwrap(); //554389
        initial_z.push(t1);
        
        let t2 = Fp::from_str_vartime("1545171245").unwrap(); //554390
        initial_z.push(t2);
        
        let t3 = Fp::from_str_vartime("1545171316").unwrap(); //554391
        initial_z.push(t3);
        
        let t4 = Fp::from_str_vartime("1545171411").unwrap(); //554392
        initial_z.push(t4);
        
        let t5 = Fp::from_str_vartime("1545172119").unwrap(); //554393
        initial_z.push(t5);
        
        let t6 = Fp::from_str_vartime("1545172682").unwrap(); //554394
        initial_z.push(t6);
        
        let t7 = Fp::from_str_vartime("1545174730").unwrap(); //554395
        initial_z.push(t7);
        
        let t8 = Fp::from_str_vartime("1545174899").unwrap(); //554396
        initial_z.push(t8);
        
        let t9 = Fp::from_str_vartime("1545174978").unwrap(); //554397
        initial_z.push(t9);
        
        let t10 = Fp::from_str_vartime("1545175153").unwrap(); //554398
        initial_z.push(t10);

        // prev target = 0x00000000000000000031d97c0000000000000000000000000000000000000000;
        let target = Fp::from_str_vartime("4774638159061819979596346127394133648234752261950013440").unwrap();
        initial_z.push(target);

        let start_time_epoch = Fp::from(1543838368);
        initial_z.push(start_time_epoch);

        let counter = Fp::from(2015u64);
        initial_z.push(counter);

        let chain_work = Fp::from(0u64);
        initial_z.push(chain_work);

        for (i, s) in initial_z.iter().enumerate() {
            z_in.push(
                AllocatedNum::alloc(cs.namespace(|| format!("z_in[{i}]")), || Ok(*s)).unwrap(),
            );
        }
        let z_out = block_554399.synthesize(&mut cs, &z_in).unwrap();
        assert_eq!(z_out.len(), 16);

        if let Some(token) = cs.which_is_unsatisfied() {
            eprintln!("Error: {} is unsatisfied", token);
        }

        assert!(cs.is_satisfied());

        let correct_start_t = AllocatedNum::alloc(cs.namespace(|| "correct start time"), || Ok(Fp::from(1337510u64))).unwrap(); 
        let r = BigNat::equals(cs.namespace(|| {"equality check"}), &z_out[13], &correct_start_t).unwrap();
        assert!(r.get_value().unwrap());
    }

    #[test]
    fn test_synthesize_for_2016_276() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        
        // block 556416
        let input: Vec<[u64; 10]>= vec![[0x00000020120b3264, 0x562d49df59c400a0, 0xf276448db2a9aa4b, 0xf6f4080000000000, 0x000000005cb4b521, 0x50fe7dec217b74db, 0x424e442ef8b24105, 0xc244ebaeb59f638d, 0xb9c48ef3c94f2a5c, 0xa5183217b412a530]];
        let mut one_block_vec:Vec<BlockHeader<Fp>> = BlockHeader::new_blocks(input);
        assert_eq!(one_block_vec.len(), 1);

        let block_556416 = one_block_vec.pop().unwrap();
        let mut z_in: Vec<AllocatedNum<Fp>> = vec![];

        let mut initial_z = Vec::new();

        // let n = 0x00000000000000000008f4f64baaa9b28d4476f2a000c459df492d5664320b12;
        let curr_hash = Fp::from_str_vartime("857898970090182581078312388832026081218915998954031890").unwrap();
        initial_z.push(curr_hash);

        // previous 11 timestamps
        let t1 = Fp::from_str_vartime("1546269544").unwrap(); //556405
        initial_z.push(t1);
        
        let t2 = Fp::from_str_vartime("1546272034").unwrap(); //556406
        initial_z.push(t2);
        
        let t3 = Fp::from_str_vartime("1546272941").unwrap(); //556407
        initial_z.push(t3);
        
        let t4 = Fp::from_str_vartime("1546273128").unwrap(); //556408
        initial_z.push(t4);
        
        let t5 = Fp::from_str_vartime("1546273329").unwrap(); //556409
        initial_z.push(t5);
        
        let t6 = Fp::from_str_vartime("1546273560").unwrap(); //556410
        initial_z.push(t6);
        
        let t7 = Fp::from_str_vartime("1546273750").unwrap(); //556411
        initial_z.push(t7);
        
        let t8 = Fp::from_str_vartime("1546273997").unwrap(); //556412
        initial_z.push(t8);
        
        let t9 = Fp::from_str_vartime("1546274625").unwrap(); //556413
        initial_z.push(t9);
        
        let t10 = Fp::from_str_vartime("1546275222").unwrap(); //556414
        initial_z.push(t10);
        
        let t11 = Fp::from_str_vartime("1546275302").unwrap(); //556415
        initial_z.push(t11);

        // prev target = 0x000000000000000000371ef40000000000000000000000000000000000000000;
        let target = Fp::from_str_vartime("5279534360700703025330663904443631645337169341976674304").unwrap();
        initial_z.push(target);

        let start_time_epoch = Fp::from(1099337);
        initial_z.push(start_time_epoch);

        let counter = Fp::from(0u64);
        initial_z.push(counter);

        let chain_work = Fp::from(0u64);
        initial_z.push(chain_work);

        for (i, s) in initial_z.iter().enumerate() {
            z_in.push(
                AllocatedNum::alloc(cs.namespace(|| format!("z_in[{i}]")), || Ok(*s)).unwrap(),
            );
        }
        let z_out = block_556416.synthesize(&mut cs, &z_in).unwrap();
        assert_eq!(z_out.len(), 16);

        if let Some(token) = cs.which_is_unsatisfied() {
            eprintln!("Error: {} is unsatisfied", token);
        }

        assert!(cs.is_satisfied());

        let correct_start_t = AllocatedNum::alloc(cs.namespace(|| "correct start time"), || Ok(Fp::from(1546276809u64))).unwrap(); 
        let r = BigNat::equals(cs.namespace(|| {"equality check"}), &z_out[13], &correct_start_t).unwrap();
        assert!(r.get_value().unwrap());
    }

    #[test]
    fn test_synthesize_for_556415() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        
        // block 556415
        let input: Vec<[u64; 10]>= vec![[0x00000020bc7d388b, 0xea14dab9caa937b9, 0x09caecd6ece36e3c, 0x6589200000000000, 0x000000007c0900cf, 0x1a9b40411141859b, 0x98bf95fb9d414f49, 0x044e08acff21fa54, 0x506022a4e6492a5c, 0xf41e3717d2864679]];
        let mut one_block_vec:Vec<BlockHeader<Fp>> = BlockHeader::new_blocks(input);
        assert_eq!(one_block_vec.len(), 1);

        let block_556416 = one_block_vec.pop().unwrap();
        let mut z_in: Vec<AllocatedNum<Fp>> = vec![];

        let mut initial_z = Vec::new();

        // let n = 0x0000000000000000002089653c6ee3ecd6ecca09b937a9cab9da14ea8b387dbc;
        let curr_hash = Fp::from_str_vartime("3116396823834000867556786151647106793502591006759484860").unwrap();
        initial_z.push(curr_hash);

        // previous 11 timestamps                
        let t11 = Fp::from_str_vartime("1546269391").unwrap(); //556404
        initial_z.push(t11);

        let t1 = Fp::from_str_vartime("1546269544").unwrap(); //556405
        initial_z.push(t1);
        
        let t2 = Fp::from_str_vartime("1546272034").unwrap(); //556406
        initial_z.push(t2);
        
        let t3 = Fp::from_str_vartime("1546272941").unwrap(); //556407
        initial_z.push(t3);
        
        let t4 = Fp::from_str_vartime("1546273128").unwrap(); //556408
        initial_z.push(t4);
        
        let t5 = Fp::from_str_vartime("1546273329").unwrap(); //556409
        initial_z.push(t5);
        
        let t6 = Fp::from_str_vartime("1546273560").unwrap(); //556410
        initial_z.push(t6);
        
        let t7 = Fp::from_str_vartime("1546273750").unwrap(); //556411
        initial_z.push(t7);
        
        let t8 = Fp::from_str_vartime("1546273997").unwrap(); //556412
        initial_z.push(t8);
        
        let t9 = Fp::from_str_vartime("1546274625").unwrap(); //556413
        initial_z.push(t9);
        
        let t10 = Fp::from_str_vartime("1546275222").unwrap(); //556414
        initial_z.push(t10);

        // prev target = 0x000000000000000000371ef40000000000000000000000000000000000000000;
        let target = Fp::from_str_vartime("5279534360700703025330663904443631645337169341976674304").unwrap();
        initial_z.push(target);

        let start_time_epoch = Fp::from(1545175965);
        initial_z.push(start_time_epoch);

        let counter = Fp::from(2015u64);
        initial_z.push(counter);

        let chain_work = Fp::from(0u64);
        initial_z.push(chain_work);

        for (i, s) in initial_z.iter().enumerate() {
            z_in.push(
                AllocatedNum::alloc(cs.namespace(|| format!("z_in[{i}]")), || Ok(*s)).unwrap(),
            );
        }
        let z_out = block_556416.synthesize(&mut cs, &z_in).unwrap();
        assert_eq!(z_out.len(), 16);

        if let Some(token) = cs.which_is_unsatisfied() {
            eprintln!("Error: {} is unsatisfied", token);
        }

        assert!(cs.is_satisfied());

        let correct_start_t = AllocatedNum::alloc(cs.namespace(|| "correct start time"), || Ok(Fp::from(1099337u64))).unwrap(); 
        let r = BigNat::equals(cs.namespace(|| {"equality check"}), &z_out[13], &correct_start_t).unwrap();
        assert!(r.get_value().unwrap());
    }
}