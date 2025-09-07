use bench_rs::{Bencher, bench};
use mysteryn_core::multibase::{decode, to_base32, to_base32pc, to_base58, to_base64, to_hex};
use std::hint::black_box;

const TEST_DATA: &[u8] = b"hello world this is a longer test string for benchmarking";

#[bench]
fn bench_encode_base32pc(b: &mut Bencher) {
    b.iter(|| {
        let _ = black_box(to_base32pc(TEST_DATA));
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_decode_base32pc(b: &mut Bencher) {
    let encoded = to_base32pc(TEST_DATA);
    b.iter(|| {
        black_box(decode(&encoded).unwrap());
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_encode_base58(b: &mut Bencher) {
    b.iter(|| {
        let _ = black_box(to_base58(TEST_DATA));
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_decode_base58(b: &mut Bencher) {
    let encoded = to_base58(TEST_DATA);
    b.iter(|| {
        black_box(decode(&encoded).unwrap());
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_encode_base64(b: &mut Bencher) {
    b.iter(|| {
        let _ = black_box(to_base64(TEST_DATA));
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_decode_base64(b: &mut Bencher) {
    let encoded = to_base64(TEST_DATA);
    b.iter(|| {
        black_box(decode(&encoded).unwrap());
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_encode_hex(b: &mut Bencher) {
    b.iter(|| {
        let _ = black_box(to_hex(TEST_DATA));
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_decode_hex(b: &mut Bencher) {
    let encoded = to_hex(TEST_DATA);
    b.iter(|| {
        black_box(decode(&encoded).unwrap());
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_encode_base32(b: &mut Bencher) {
    b.iter(|| {
        let _ = black_box(to_base32(TEST_DATA));
    });
    b.bytes = TEST_DATA.len();
}

#[bench]
fn bench_decode_base32(b: &mut Bencher) {
    let encoded = to_base32(TEST_DATA);
    b.iter(|| {
        black_box(decode(&encoded).unwrap());
    });
    b.bytes = TEST_DATA.len();
}
