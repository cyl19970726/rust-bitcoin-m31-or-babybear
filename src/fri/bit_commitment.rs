//
// Winternitz One-time Signatures
//

//
// Winternitz signatures are an improved version of Lamport signatures.
// A detailed introduction to Winternitz signatures can be found
// in "A Graduate Course in Applied Cryptography" in chapter 14.3
// https://toc.cryptobook.us/book.pdf
//
// We are trying to closely follow the authors' notation here.
//

//
// BEAT OUR IMPLEMENTATION AND WIN A CODE GOLF BOUNTY!
//

pub use crate::execute_script;
pub use bitcoin_script::{define_pushable, script};

define_pushable!();
use bitcoin::ScriptBuf as Script;

use bitcoin::hashes::{hash160, Hash};
use hex::decode as hex_decode;
// 0000 ~ 1111 (0~15)

// vcalue  0001  0010  0011  0100
// secret   A     B     C     D
// maxCheckum = 15 x 4 = 60  need 6bit
// checksum = 1 + 2 +3 +4 = 10  (has 6 preimage)
// pubkey    = Hash_256(A) HASH_256(B) HASH_256(C) HASH_256(D)
// signature = Hash_1(A)  Hash_2(B)    Hash_3(C)   Hash_4(D)    checksum = {nil nil preiamge nil preimage nil }
// verify :
//    HASH_255(HASH_1(A)) ==  Hash_256(A) HASH_254(HASH_2(B)) == HASH_256(B) HASH_253(HASH_3(C)) == HASH_256(C) HASH_252(HASH_4(D)) == HASH_256(D)
//    reveal preiamge for checksum and must to equal to 10

// /// Bits per digit
// const LOG_D: u32 = 4;
// /// Digits are base d+1
// pub const D: u32 = (1 << LOG_D) - 1;
// /// Number of digits of the message (20x15=300 checksum need 9bits)
// pub const N0: u32 = 20;
// /// Number of digits of the checksum
// pub const N1: usize = 4;
// /// Total number of digits to be signed
// pub const N: u32 = N0 + N1 as u32;

/// Bits per digit
const LOG_D: u32 = 4;
/// Digits are base d+1
pub const D: u32 = (1 << LOG_D) - 1;
/// Number of digits of the message (8x15=120 checksum need 7bits(2 digits))
pub const N0: usize = 8;
/// Number of digits of the checksum
pub const N1: usize = 2;
/// Total number of digits to be signed
pub const N: u32 = (N0 + N1) as u32;

//
// Helper functions
//

/// Generate the public key for the i-th digit of the message
pub fn public_key(secret_key: &str, digit_index: u32) -> Vec<u8> {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    hash.as_byte_array().to_vec()
}

/// Generate the public key for the i-th digit of the message
pub fn public_key_script(secret_key: &str, digit_index: u32) -> Script {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
    }
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u8) -> (Vec<u8>, u8) {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    (hash_bytes, message_digit)
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature_script(secret_key: &str, digit_index: u32, message_digit: u8) -> Script {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
        { message_digit }
    }
}

/// Compute the checksum of the message's digits.
/// Further infos in chapter "A domination free function for Winternitz signatures"
pub fn checksum(digits: [u8; N0 as usize]) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    D * N0 as u32 - sum
}

/// Convert a number to digits
pub fn to_digits<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D + 1);
        number = (number - digit) / (D + 1);
        digits[i] = digit as u8;
    }
    digits
}

/// Compute the signature for a given message
pub fn sign(secret_key: &str, message_digits: [u8; N0 as usize]) -> Vec<Vec<u8>> {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    let mut signature: Vec<Vec<u8>> = Vec::new();
    for i in 0..N {
        let (hash, digit) = digit_signature(secret_key, i, checksum_digits[(N - 1 - i) as usize]);
        signature.push(hash); // The reason why reverse order is used here is because it needs to be pushed onto the stack
        signature.push(vec![digit]);
    }
    assert!(signature.len() == 2 * N as usize);
    signature
}

/// Compute the signature for a given message
pub fn sign_script(secret_key: &str, message_digits: [u8; N0 as usize]) -> Script {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    script! {
        for i in 0..N {
            { digit_signature_script(secret_key, i, checksum_digits[ (N-1-i) as usize]) } // The reason why reverse order is used here is because it needs to be pushed onto the stack
        }
    }
}

///  Locking Script for a Winternitz signature
pub fn checksig_verify(pub_key: &[Vec<u8>]) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..N {
            // Verify that the digit is in the range [0, d]
            OP_DUP
            0
            { D + 1 }
            OP_WITHIN
            OP_VERIFY

            // Push two copies of the digit onto the altstack
            OP_DUP
            OP_TOALTSTACK
            OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            for _ in 0..D {
                OP_DUP OP_HASH160
            }

            // Verify the signature for this digit
            OP_FROMALTSTACK
            OP_PICK
            { pub_key[(N - 1 - digit_index) as usize].clone() }
            OP_EQUALVERIFY

            // Drop the d+1 stack items
            for _ in 0..(D+1)/2 {
                OP_2DROP
            }
        }


        //
        // Verify the Checksum
        //

        // 1. Compute the checksum of the message's digits
        0
        for _ in 0..N0 {
            OP_FROMALTSTACK OP_DUP OP_ROT OP_ADD
        }
        { D * N0 as u32 }
        OP_SWAP
        OP_SUB


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..N1 - 1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY

        // Because the 2LOG_D equal to 1 byte
        // Convert the message's digits to bytes
        for _ in 0..N0 / 2 {
            OP_SWAP
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_ADD
            OP_TOALTSTACK
        }
        for _ in 0..N0 / 2 {
            OP_FROMALTSTACK
        }

    }
}

#[cfg(test)]
mod test {
    use bitcoin::ecdsa::Signature;

    use crate::execute_script_with_inputs;

    use super::*;

    // The secret key
    const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7"; // 20 byte

    #[test]
    fn test_winternitz() {
        // The message to sign
        // const MESSAGE: [u8; 20] = [
        //     1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0, 0, 0, 0, 0,
        // ];

        // let MESSAGE = to_digits::<8>(99992921);
        // print!("{:?}", MESSAGE);

        // the origin value is [1000,0111,0110,0101,0100,0011,0010,0001]
        // for the u8 resprentation [0x87,0x65,0x43,0x21]
        let origin_value: u32 = 0x87654321;
        let message = to_digits::<N0>(origin_value);
        const MESSAGE: [u8; N0 as usize] = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(message, MESSAGE);

        let mut pubkey = Vec::new();
        for i in 0..N {
            pubkey.push(public_key(MY_SECKEY, i as u32));
        }

        let script = script! {
            { sign_script(MY_SECKEY, MESSAGE) } // digit 0 = [checkum hash_i]
            { checksig_verify(pubkey.as_slice()) }// using secret key to generate pubkey

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUAL
        };

        println!(
            "Winternitz signature size: {:?} bytes per 80 bits",
            script.as_bytes().len()
        );
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_winternitz_with_input() {

        const MESSAGE: [u8; N0 as usize] = [1, 2, 3, 4, 5, 6, 7, 8];

        let mut pubkey = Vec::new();
        for i in 0..N {
            pubkey.push(public_key(MY_SECKEY, i as u32));
        }

        println!("{:?}", sign_script(MY_SECKEY, MESSAGE).to_string());
        let script = script! {
            { checksig_verify(pubkey.as_slice()) }// using secret key to generate pubkey

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            OP_1
        };

        println!(
            "Winternitz signature size: {:?} bytes per 80 bits",
            script.as_bytes().len()
        );

        let sig = sign(MY_SECKEY, MESSAGE);
        let exec_result = execute_script_with_inputs(script, sig);
        assert!(exec_result.success);

        // Message Checking
        const MESSAGE_1: [u8; N0 as usize] = [0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 8];

        let mut pubkey = Vec::new();
        for i in 0..N {
            pubkey.push(public_key(MY_SECKEY, i as u32));
        }

        println!("{:?}", sign_script(MY_SECKEY, MESSAGE_1).to_string());
        let script = script! {
            { checksig_verify(pubkey.as_slice()) }// using secret key to generate pubkey

            0xBA OP_EQUALVERIFY
            0xDC OP_EQUALVERIFY
            0xFE OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            OP_1
        };

        println!(
            "Winternitz signature size: {:?} bytes per 80 bits",
            script.as_bytes().len()
        );

        println!("{:?}",script);

        let sig = sign(MY_SECKEY, MESSAGE_1);
        let exec_result = execute_script_with_inputs(script, sig);
        assert!(exec_result.success);
    }
}
