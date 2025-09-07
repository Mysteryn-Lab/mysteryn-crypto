use bench_rs::{Bencher, bench};
use mysteryn_core::varint::{decode_varint_u64, encode_varint_u64};
use std::hint::black_box;

#[bench]
fn bench_encode_varint(b: &mut Bencher) {
    let num = u64::MAX;
    b.iter(|| {
        let _ = black_box(encode_varint_u64(num));
    });
}

#[bench]
fn bench_decode_varint(b: &mut Bencher) {
    let encoded = encode_varint_u64(u64::MAX);
    b.iter(|| {
        black_box(decode_varint_u64(&encoded).unwrap());
    });
}
