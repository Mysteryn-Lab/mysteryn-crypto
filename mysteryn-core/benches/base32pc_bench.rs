use bench_rs::{Bencher, bench};
use mysteryn_core::base32pc::{decode, decode_constant, encode, encode_constant};
use std::hint::black_box;

#[bench]
fn bench_encode_base32pc(b: &mut Bencher) {
    let data = [0u8; 1000];
    b.iter(|| {
        let _ = black_box(encode("test", &data));
    });
    b.bytes = data.len();
}

#[bench]
fn bench_decode_base32pc(b: &mut Bencher) {
    let data = [0u8; 1000];
    let encoded = encode("test", &data);
    b.iter(|| {
        black_box(decode(&encoded).unwrap());
    });
    b.bytes = data.len();
}

#[bench]
fn bench_encode_constant_base32pc(b: &mut Bencher) {
    let data = [0u8; 1000];
    b.iter(|| {
        let _ = black_box(encode_constant("did:key:xa", &data));
    });
    b.bytes = data.len();
}

#[bench]
fn bench_decode_constant_base32pc(b: &mut Bencher) {
    let data = [0u8; 1000];
    let encoded = encode_constant("did:key:xa", &data);
    b.iter(|| {
        black_box(decode_constant("did:key:xa", &encoded).unwrap());
    });
    b.bytes = data.len();
}
