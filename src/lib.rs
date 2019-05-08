extern crate libc;
extern crate accumulator;

use accumulator::{Accumulator,MembershipProof};
use accumulator::group::Rsa2048;
use std::mem::transmute;
use std::slice;

#[no_mangle]
pub extern "C" fn make_accumulator() -> *const Accumulator<Rsa2048, Vec<u8>> {
    let accumulator = unsafe { transmute(Box::new(Accumulator::<Rsa2048, Vec<u8>>::empty())) };
    accumulator
}

#[no_mangle]
pub extern "C" fn add_with_proof(
    accumulator_ptr: *const Accumulator<Rsa2048, Vec<u8>>, 
    to_add: Vec<u8>
) -> (*const Accumulator<Rsa2048, Vec<u8>>, *const MembershipProof<Rsa2048,Vec<u8>>) {
    let accumulator: Box<Accumulator<Rsa2048, Vec<u8>>> = unsafe { transmute(accumulator_ptr) };
    let (new_acc, proof) = accumulator.add_with_proof(&[to_add]);

    let new_acc_ptr = unsafe { transmute(Box::new(new_acc)) };
    let proof_ptr = unsafe { transmute(Box::new(proof)) };

    (new_acc_ptr, proof_ptr)
}

#[no_mangle]
pub extern "C" fn verify_membership_batch(
    items_ptr: *const u8,
    items_len: u32,
    accumulator_ptr: *const Accumulator<Rsa2048, Vec<u8>>, 
    membership_proof_ptr: *const MembershipProof<Rsa2048,Vec<u8>>
) -> bool {
    let items: Vec<u8> = unsafe{ slice::from_raw_parts(items_ptr, items_len as usize).to_vec() };
    let accumulator: Box<Accumulator<Rsa2048, Vec<u8>>> = unsafe { transmute(accumulator_ptr) };
    let prf : Box<MembershipProof<Rsa2048,Vec<u8>>> = unsafe { transmute(membership_proof_ptr) };

    accumulator.verify_membership_batch(&[items], &prf)
}