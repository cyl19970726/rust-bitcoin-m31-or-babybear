// the leaf script maybe include
// different field [M31, BabyBear, Babybear EXTField]
// one evaluation from one polynomial or multiple evaluations from multi-polynomials
// different bit-commitment
// how to searlize the leaf
// use which hash to hash the leaf script

use std::marker::PhantomData;
use std::usize;

use super::bit_commitment::*;
use ::bitcoin_script as script;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::ScriptBuf as Script;
use winterfell::crypto::{ElementHasher, Hasher, RandomCoin};
use winterfell::math::{fields::f64::BaseElement, FieldElement};

// trait Leaf<const NUM_POLY:usize> {
//     fn eval(&self, x: u32) -> u32;
//     fn serialize(&self) -> Vec<u8>;
//     fn hash(&self) -> Vec<u8>;
// }

struct EvaluationLeaf<const NUM_POLY: usize, F: FieldElement, const FIELD_SIZE: usize> {
    leaf_index: usize,
    x: u32,
    x_commitment: BitCommitment<F>,
    evaluations: Vec<u32>,
    evaluations_commitments: Vec<BitCommitment<F>>,
}

impl<const NUM_POLY: usize, F: FieldElement, const FIELD_SIZE: usize>
    EvaluationLeaf<NUM_POLY, F, FIELD_SIZE>
{
    fn new(leaf_index: usize, x: u32, evaluations: Vec<u32>) -> Self {
        assert_eq!(evaluations.len(), NUM_POLY);

        let x_commitment =
            BitCommitment::new("b138982ce17ac813d505b5b40b665d404e9528e8".to_string(), x);
        let mut evaluations_commitments = Vec::new();
        for i in 0..NUM_POLY {
            evaluations_commitments.push(BitCommitment::new(
                "b138982ce17ac813d505b5b40b665d404e9528e9".to_string(),
                evaluations[i],
            ));
        }

        Self {
            leaf_index,
            x,
            x_commitment,
            evaluations,
            evaluations_commitments,
        }
    }

    fn leaf_script(&self) -> Script {
        // equal to x script
        let scripts = script! {
            { self.x_commitment.checksig_verify_script() }
            { self.x_commitment.check_equal_script() }
            // todo: calculate to equal to -x
            for i in 0..NUM_POLY{
                { self.evaluations_commitments[NUM_POLY-1-i].checksig_verify_script() }
                { self.evaluations_commitments[NUM_POLY-1-i].check_equal_script() }
            }
            OP_1
        };

        scripts
    }
}
struct BitCommitment<F: FieldElement> {
    origin_value: u32,
    secret_key: String,
    message: [u8; N0 as usize], // every u8 only available for 4-bits
    commit_message: [u8; N0 / 2 as usize],
    pubkey: Vec<Vec<u8>>,
    _marker: PhantomData<F>,
}

impl<F: FieldElement> BitCommitment<F> {
    pub fn new(secret_key: String, origin_value: u32) -> Self {
        let message = to_digits::<N0>(origin_value);
        let mut commit_message = [0; N0 / 2];
        for i in 0..N0 / 2 {
            let index = N0 / 2 - 1 - i;
            commit_message[i] = message[2 * index] ^ (message[2 * index + 1] << 4);
        }
        let mut pubkey = Vec::new();
        for i in 0..N {
            pubkey.push(public_key(&secret_key, i as u32));
        }
        Self {
            origin_value,
            secret_key,
            message,
            commit_message,
            pubkey,
            _marker: PhantomData,
        }
    }

    pub fn check_equal_script(&self) -> Script {
        script! {
            for i in 0..N0/2{
                {self.commit_message[ N0 / 2 - 1 - i]} OP_EQUALVERIFY
            }
        }
    }

    pub fn checksig_verify_script(&self) -> Script {
        checksig_verify(self.pubkey.as_slice())
    }

    // signuture is the input of this script
    pub fn complete_script(&self) -> Script {
        script! {
            {self.checksig_verify_script()}
            {self.check_equal_script()}
        }
    }

    pub fn signature_script(&self) -> Script {
        sign_script(&self.secret_key, self.message)
    }

    pub fn signature(&self) -> Vec<Vec<u8>> {
        sign(&self.secret_key, self.message)
    }
}

pub fn u8_to_hex_str(byte: &u8) -> String {
    format!("{:02X}", byte)
}

#[cfg(test)]
mod test {
    use crate::execute_script_with_inputs;

    use super::*;

    #[test]
    fn test_leaf() {
        const num_polys: usize = 2;
        let leaf = EvaluationLeaf::<num_polys, BaseElement, 2>::new(
            0,
            0x87654321,
            vec![0x87654321, 0x87654321],
        );
        let script = leaf.leaf_script();

        let mut sigs: Vec<Vec<u8>> = Vec::new();
        for i in 0..num_polys {
            let mut signature = leaf.evaluations_commitments[num_polys - 1 - i].signature();
            signature.iter().for_each(|item| sigs.push(item.to_vec()));
        }
        let mut signature = leaf.x_commitment.signature();
        signature.iter().for_each(|item| sigs.push(item.to_vec()));

        println!("{:?}", script);

        let exec_result = execute_script_with_inputs(script, sigs);
        assert!(exec_result.success);
    }

    #[test]
    fn test_bit_commitment() {
        const num_polys: usize = 1;
        let leaf =
            EvaluationLeaf::<num_polys, BaseElement, 2>::new(0, 0x87654321, vec![0x87654321]);

        assert_eq!(leaf.x_commitment.commit_message, [0x87, 0x65, 0x43, 0x21]);
        println!("{:?}", leaf.x_commitment.commit_message);

        let check_equal_script = leaf.x_commitment.check_equal_script();
        println!("{:?}", check_equal_script);

        let expect_script = script! {
            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
        };

        assert_eq!(expect_script, check_equal_script);

        // check signature and verify the value
        let mut signature = leaf.x_commitment.signature();
        let exec_scripts = script! {
            { leaf.x_commitment.checksig_verify_script() }
            { leaf.x_commitment.check_equal_script() }
            OP_1
        };
        println!("{:?}", exec_scripts);
        let exec_result = execute_script_with_inputs(exec_scripts, signature);
        assert!(exec_result.success);
    }
}
