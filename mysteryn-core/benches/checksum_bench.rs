use bench_rs::{Bencher, bench};
use mysteryn_core::error_correction::checksum::{
    append, correct_approximately, decode, get_checksum,
};
use std::hint::black_box;

#[bench]
fn bench_append_checksum(b: &mut Bencher) {
    let data = [0u8; 1000];
    b.iter(|| {
        let _ = black_box(append(&data));
    });
    b.bytes = data.len();
}

#[bench]
fn bench_get_checksum(b: &mut Bencher) {
    let data = [0u8; 1000];
    b.iter(|| {
        let _ = black_box(get_checksum(&data));
    });
    b.bytes = data.len();
}

#[bench]
fn bench_decode_checksum(b: &mut Bencher) {
    let data = [0u8; 1000];
    let encoded = append(&data);
    b.iter(|| {
        black_box(decode(&encoded).unwrap());
    });
    b.bytes = data.len();
}

#[bench]
fn bench_correct_approximately_checksum(b: &mut Bencher) {
    let data = [0u8; 1000];
    let mut encoded = append(&data);
    // Introduce an error
    encoded[10] = encoded[10].wrapping_add(1);
    b.iter(|| {
        black_box(correct_approximately(&encoded).unwrap());
    });
    b.bytes = data.len();
}
