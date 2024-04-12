use std::usize;

use crate::fri::NativeField;
use crate::{pushable, unroll};
use bitcoin::opcodes::{OP_ADD, OP_LSHIFT, OP_SWAP};
use bitcoin::{
    opcodes::{OP_FROMALTSTACK, OP_TOALTSTACK},
    ScriptBuf as Script,
};
use bitcoin_script::script;
mod m31;
pub use m31::*;

mod babybear;
pub use babybear::*;


use crate::fri::bit_commitment::{D,LOG_D,LOG_D_usize,N0,N1,N};

pub trait U31Config {
    const MOD: u32;
}

fn u31_adjust<M: U31Config>() -> Script {
    script! {
        OP_DUP
        0 OP_LESSTHAN
        OP_IF { M::MOD } OP_ADD OP_ENDIF
    }
}

pub fn u31_add<M: U31Config>() -> Script {
    script! {
        { M::MOD } OP_SUB
        OP_ADD
        { u31_adjust::<M>() }
    }
}

pub fn u31_double<M: U31Config>() -> Script {
    script! {
        OP_DUP
        { u31_add::<M>() }
    }
}

pub fn u31_sub<M: U31Config>() -> Script {
    script! {
        OP_SUB
        { u31_adjust::<M>() }
    }
}

pub fn u31_to_bits() -> Script {
    script! {
        {
            unroll(30, |i| {
                let a = 1 << (30 - i);
                let b = a - 1;
                script! {
                    OP_DUP
                    { b } OP_GREATERTHAN
                    OP_SWAP OP_OVER
                    OP_IF { a } OP_SUB OP_ENDIF
                }
        })}
    }
}

pub fn u31_mul<M: U31Config>() -> Script {
    script! {
        u31_to_bits
        { unroll(31, |_| script! {
            OP_TOALTSTACK
        }) }
        0
        OP_SWAP
        OP_DUP
        { u31_double::<M>() }
        OP_2DUP
        { u31_add::<M>() }
        0
        OP_FROMALTSTACK
        OP_IF
            3 OP_PICK
            { u31_add::<M>() }
        OP_ENDIF
        { u31_double::<M>() }
        { u31_double::<M>() }
        { unroll(14, |_| script! {
            OP_FROMALTSTACK
            OP_FROMALTSTACK
            OP_SWAP OP_DUP OP_ADD OP_ADD
            4 OP_SWAP OP_SUB OP_PICK
            { u31_add::<M>() }
            { u31_double::<M>() }
            { u31_double::<M>() }
        })}
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_SWAP OP_DUP OP_ADD OP_ADD
        4 OP_SWAP OP_SUB OP_PICK
        { u31_add::<M>() }
        OP_TOALTSTACK
        OP_2DROP OP_2DROP
        OP_FROMALTSTACK
    }
}

pub fn convert_digits_to_u31<M:U31Config,const DIGITS_BITSIZE:usize,const DIGITS_NUM:usize>() -> Script{
    //0x87654321; 
    // The stack before convert_D_to_u31 looks like(DIGITS_BITSIZE=8,DIGITS_NUM=4 ): 
    // 0x21 
    // 0x43 
    // 0x65 
    // 0x87 
    script!{
        // The Top Element of the stack is the lowest-bit-value and does not need to be dealed.
        OP_TOALTSTACK
        for i in 1..DIGITS_NUM-1{
            // STACK:[a,b]  OP_LSHIFT:Logical left shift b bits. Sign data is discarded
            {DIGITS_BITSIZE} 
            OP_SWAP 
            OP_LSHIFT
            OP_FROMALTSTACK
            OP_ADD
            OP_TOALTSTACK
        }
        // The ADD operation happened at the final maybe exceed MOD, using u31_ADD here.
        {DIGITS_BITSIZE} 
        OP_SWAP 
        OP_LSHIFT
        OP_FROMALTSTACK
        {u31_add::<M>()}
    }
}

pub fn convert_digits_to_u32<const DIGITS_BITSIZE:usize,const DIGITS_NUM:usize>() -> Script{
    //0x87654321; 
    // The stack before convert_D_to_u31 looks like(DIGITS_BITSIZE=8,DIGITS_NUM=4 ): 
    // 0x21 
    // 0x43 
    // 0x65 
    // 0x87 
    script!{
        // The Top Element of the stack is the lowest-bit-value and does not need to be dealed.
        OP_TOALTSTACK
        for i in 1..DIGITS_NUM{
            // STACK:[a,b]  OP_LSHIFT:Logical left shift b bits. Sign data is discarded
            {DIGITS_BITSIZE} 
            OP_SWAP 
            OP_LSHIFT
            OP_FROMALTSTACK
            OP_ADD
            OP_TOALTSTACK
        }
    }
}

// y_0(r)= g_0,1(r^2) + r g_0,2(r^2)
// y_0(-r)= g_0,1(r^2) -r g_0,2(r^2)
// y_1(r^2) = g_0,1(r^2) + v_0 g_0,2(r^2)
pub fn fold_degree<M: U31Config, F: NativeField>(
    degree: u32,
    x: F,
    y_0_x: F,
    y_0_neg_x: F,
    v_0: F,
    y_1_x_quare: F,
) -> Script {
    script! {

        // calculate 2 * g_0,1(r^2)
        {y_0_x.as_u32()}
        {y_0_neg_x.as_u32()}
        { u31_add::<M>() }
        // calculate 2 * r * g_0,1(r^2)
        { x.as_u32()}
        { u31_mul::<M>()}
        OP_TOALTSTACK

        // calculate 2 * r * g_0,2(r^2)
        {y_0_x.as_u32()}
        {y_0_neg_x.as_u32()}
        { u31_sub::<M>() }
        // calculate 2 * r * v_0 * g_0,2(r^2)
        {v_0.as_u32()}
        {u31_mul::<M>()}
        OP_FROMALTSTACK
        { u31_add::<M>() }
        OP_TOALTSTACK

        // calculate 2*r*y_1(r^2)
        {y_1_x_quare.as_u32()}
        {u31_double::<M>()}
        {x.as_u32()}
        {u31_mul::<M>()}

        // Check Equal
        // y_1(r^2) = g_0,1(r^2) + v_0 g_0,2(r^2)
        // 2r y_1(r^2) = 2r g_0,1(r^2) + 2r v_0 g_0,2(r^2)
        OP_FROMALTSTACK
        OP_EQUAL
    }
}

#[cfg(test)]
mod test {
    use crate::execute_script;
    use bitcoin::{opcodes::OP_EQUAL, Script};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn test_convert_digits_to_u32(){

        // check LSHIFT 
        let shift_script = script!{
            {8 as u32}
            {20 as u32}// 0x14
            // OP_RSHIFT
            {(20*256) as u32} // 0x1400 => 0x0014 
            OP_EQUAL
        };

        // let shift_script = Script::parse_asm("OP_PUSHNUM_8 OP_PUSHBYTES_1 14 OP_LSHIFT OP_PUSHBYTES_2 1400 OP_EQUAL").unwrap();
            // shift_script
        println!("{:?}",shift_script.clone());
        let exec_result = execute_script(shift_script);
        assert!(exec_result.success);
        let script = script!{
            0x87
            0x65 
            0x43
            0x21 
  
            {convert_digits_to_u32::<8,N0>()}
            OP_FROMALTSTACK
            0x87654321 OP_EQUAL
        };

        println!("{:?}",script);

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u32_add() {
        let v1: u32 = 0x1BCDEF12;
        let v2: u32 = 0x1BCDEF00;
        let v1_babybear = v1 % BabyBear::MOD;
        let v2_babybear = v2 % BabyBear::MOD;
        let sum_babybear = (v1_babybear + v2_babybear) % BabyBear::MOD;
        let script = script! {
            { v1_babybear }
            { v2_babybear }
            { u31_add::<M31>() }
            { sum_babybear }
            OP_EQUAL
        };
        println!("{:}", script);
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u31_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0u64);
        eprintln!("u31 add: {}", u31_add::<BabyBear>().len());

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_m31 = a % M31::MOD;
            let b_m31 = b % M31::MOD;
            let sum_m31 = (a_m31 + b_m31) % M31::MOD;

            let script = script! {
                { a_m31 }
                { b_m31 }
                { u31_add::<M31>() }
                { sum_m31 }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_babybear = a % BabyBear::MOD;
            let b_babybear = b % BabyBear::MOD;
            let sum_babybear = (a_babybear + b_babybear) % BabyBear::MOD;

            let script = script! {
                { a_babybear }
                { b_babybear }
                { u31_add::<BabyBear>() }
                { sum_babybear }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success)
        }
    }

    #[test]
    fn test_u31_sub() {
        let mut prng = ChaCha20Rng::seed_from_u64(0u64);
        eprintln!("u31 sub: {}", u31_sub::<BabyBear>().len());

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_m31 = a % M31::MOD;
            let b_m31 = b % M31::MOD;
            let diff_m31 = (M31::MOD + a_m31 - b_m31) % M31::MOD;

            let script = script! {
                { a_m31 }
                { b_m31 }
                { u31_sub::<M31>() }
                { diff_m31 }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_babybear = a % BabyBear::MOD;
            let b_babybear = b % BabyBear::MOD;
            let diff_babybear = (BabyBear::MOD + a_babybear - b_babybear) % BabyBear::MOD;

            let script = script! {
                { a_babybear }
                { b_babybear }
                { u31_sub::<BabyBear>() }
                { diff_babybear }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success)
        }
    }

    #[test]
    fn test_u31_to_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0u64);

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let m31 = a % M31::MOD;

            let mut bits = vec![];
            let mut cur = m31;
            for _ in 0..31 {
                bits.push(cur % 2);
                cur >>= 1;
            }
            assert_eq!(cur, 0);

            let script = script! {
                { m31 }
                u31_to_bits
                { unroll(30, |i| script! {
                    { bits[i as usize] } OP_EQUALVERIFY
                })}
                { bits[30] } OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let babybear = a % BabyBear::MOD;

            let mut bits = vec![];
            let mut cur = babybear;
            for _ in 0..31 {
                bits.push(cur % 2);
                cur >>= 1;
            }
            assert_eq!(cur, 0);

            let script = script! {
                { babybear }
                u31_to_bits
                { unroll(30, |i| script! {
                    { bits[i as usize] } OP_EQUALVERIFY
                })}
                { bits[30] } OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_u31_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(6u64);
        eprintln!("u31 mul: {}", u31_mul::<BabyBear>().len());

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_m31 = a % M31::MOD;
            let b_m31 = b % M31::MOD;
            let prod_m31 =
                ((((a_m31 as u64) * (b_m31 as u64)) % (M31::MOD as u64)) & 0xffffffff) as u32;

            let script = script! {
                { a_m31 }
                { b_m31 }
                { u31_mul::<M31>() }
                { prod_m31 }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u32 = prng.gen();
            let b: u32 = prng.gen();

            let a_babybear = a % BabyBear::MOD;
            let b_babybear = b % BabyBear::MOD;
            let prod_babybear = ((((a_babybear as u64) * (b_babybear as u64))
                % (BabyBear::MOD as u64))
                & 0xffffffff) as u32;

            let script = script! {
                { a_babybear }
                { b_babybear }
                { u31_mul::<BabyBear>() }
                { prod_babybear }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success)
        }
    }
}
