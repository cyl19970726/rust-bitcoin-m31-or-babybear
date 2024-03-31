// the leaf script maybe include
// different field [M31, BabyBear, Babybear EXTField]
// one evaluation from one polynomial or multiple evaluations from multi-polynomials
// different bit-commitment
// how to searlize the leaf 
// use which hash to hash the leaf script

use std::usize;

use bitcoin::ScriptBuf as Script;
use ::bitcoin_script as script;
use p3_field::Field;
use winterfell::math::FieldElement;
use winterfell::crypto::{ElementHasher, Hasher, RandomCoin};


trait Leaf<const NUM_POLY:usize> {
    fn eval(&self, x: u32) -> u32;
    fn serialize(&self) -> Vec<u8>;
    fn hash(&self) -> Vec<u8>;
}

struct LeafData<const NUM_POLY:usize,F:FieldElement,const FIELD_SIZE: usize,B: BitCommitment<F,FIELD_SIZE>>{
    evaluations: [Vec<F>;NUM_POLY],
    commitments: [B;NUM_POLY],
}

trait BitCommitment<F: Sized,H: Hasher,const FIELD_SIZE:usize>: From<F> {
    type Hasher: Hasher;
    fn bits(&self) -> [bool;FIELD_SIZE];
    fn commit(&self,seed: u32) -> Vec<u8>;
    fn reveal(&self) -> Vec<u8>;
    fn reveal_script(&self) -> Script;
}

type Preimage = [u8;32];
struct HashBitCommitment<F: FieldElement,H: Hasher,const FIELD_SIZE:usize> {
    origin_value: F,
    bits: [bool; FIELD_SIZE],
    commitment0: [H::Digest;FIELD_SIZE],
    commitment1: [H::Digest;FIELD_SIZE],
    reveal0: [Preimage;FIELD_SIZE],
    reveal1: [Preimage;FIELD_SIZE],
}   


impl<F:FieldElement,H: Hasher,const FIELD_SIZE:usize> From<F> for HashBitCommitment<F,H,FIELD_SIZE>{
    fn from(value: F) -> Self {
        value
        Self{
            origin_value: value,
            bits: [false;FIELD_SIZE],
            commitment: [Default::default();FIELD_SIZE],
            reveal: [Default::default();FIELD_SIZE],
        }
    }
}
    
impl<F:FieldElement,H: Hasher,const FIELD_SIZE:usize> BitCommitment<F,FIELD_SIZE> for HashBitCommitment<F,H,FIELD_SIZE>{
    fn bits(&self) -> [bool;FIELD_SIZE]{
        [false;FIELD_SIZE]
    }


    fn commit(&self) -> Vec<u8>{
       self.bits().iter().map(|b| if *b {1} else {0}).collect()
    }
    fn reveal(&self) -> Vec<u8>{
        unimplemented!()
    }
}
trait FieldSize{
    const FIELD_SIZE:usize;
    // const fn field_size(&self)-> usize;
}

