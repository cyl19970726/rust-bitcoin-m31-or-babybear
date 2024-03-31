
// the leaf script maybe include
// different field [M31, BabyBear, Babybear EXTField]
// one evaluation from one polynomial or multiple evaluations from multi-polynomials
// different bit-commitment
// how to searlize the leaf 
// use which hash to hash the leaf script

use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use p3_field::Field;
use crate::winterfell::math::field::FieldElement;
use crate::winterfell::crypto::{ElementHasher, Hasher, RandomCoin};


trait Leaf<const NUM_POLY:usize> {
    fn eval(&self, x: u32) -> u32;
    fn serialize(&self) -> Vec<u8>;
    fn hash(&self) -> Vec<u8>;
}

struct LeafData<const NUM_POLY:usize,F:FieldSize,B: BitCommitment<F>>{
    evaluations: [Vec<F>;NUM_POLY],
    commitments: [B;NUM_POLY],
}

trait BitCommitment<F: Sized>: From<F> {
    fn bits(&self) -> Vec<bool>;
    fn commit(&self) -> Vec<u8>;
    fn reveal(&self) -> Vec<u8>;
    fn reveal_script(&self) -> Script;
}

type Hash = [u8;32];
type Preimage = [u8;32];
struct HashBitCommitment<F: Sized,const FIELD_SIZE:usize> {
    origin_value: F,
    bits: [bool; FIELD_SIZE],
    commitment: [Hash;FIELD_SIZE],
    reveal: [Preimage;FIELD_SIZE],
}   


impl<F:Sized,const FIELD_SIZE:usize> From<F> for HashBitCommitment<F,FIELD_SIZE>{
    fn from(value: F) -> Self {
        Self{
            origin_value: value,
            bits: [false;FIELD_SIZE],
            commitment: [Default::default();FIELD_SIZE],
            reveal: [Default::default();FIELD_SIZE],
        }
    }
}
    
impl<F:Sized,const FIELD_SIZE:usize> BitCommitment<F> for HashBitCommitment<F,FIELD_SIZE>{
    fn commit(&self) -> Vec<u8>{
        unimplemented!()
    }
    fn reveal(&self) -> Vec<u8>{
        unimplemented!()
    }
}
trait FieldSize{
    const FIELD_SIZE:usize;
    // const fn field_size(&self)-> usize;
}

