use bench_rs::{Bencher, bench};
use mysteryn_core::attributes::{KeyAttributes, SignatureAttributes};
use std::hint::black_box;

#[bench]
fn bench_key_attributes_to_writer(b: &mut Bencher) {
    let mut attributes = KeyAttributes::new();
    attributes.set_key_is_encrypted(true);
    attributes.set_key_data(Some(&[1, 2, 3]));
    attributes.set_algorithm_name(Some("test-algo"));
    attributes.set_key_type(Some(1));
    attributes.set_public_hrp(Some("hrp"));

    let mut bytes = 0;
    b.iter(|| {
        let mut buffer = Vec::new();
        attributes.to_writer(black_box(&mut buffer)).unwrap();
        if bytes == 0 {
            bytes = buffer.len();
        }
    });
    b.bytes = bytes;
}

#[bench]
fn bench_key_attributes_from_reader(b: &mut Bencher) {
    let mut attributes = KeyAttributes::new();
    attributes.set_key_is_encrypted(true);
    attributes.set_key_data(Some(&[1, 2, 3]));
    attributes.set_algorithm_name(Some("test-algo"));
    attributes.set_key_type(Some(1));
    attributes.set_public_hrp(Some("hrp"));

    let mut buffer = Vec::new();
    attributes.to_writer(&mut buffer).unwrap();

    b.iter(|| {
        let mut reader = std::io::Cursor::new(buffer.as_slice());
        let _ = black_box(KeyAttributes::from_reader(&mut reader).unwrap());
    });
    b.bytes = buffer.len();
}

#[bench]
fn bench_signature_attributes_to_writer(b: &mut Bencher) {
    let mut attributes = SignatureAttributes::new();
    attributes.set_signature_data(Some(&[1, 2, 3]));
    attributes.set_payload_encoding(Some(123));
    attributes.set_scheme(Some(456));
    attributes.set_algorithm_name(Some("test-sig-algo"));
    attributes.set_nonce(Some(&[7, 8, 9]));
    attributes.set_public_key(Some(&[10, 11, 12]));

    let mut bytes = 0;
    b.iter(|| {
        let mut buffer = Vec::new();
        attributes.to_writer(black_box(&mut buffer)).unwrap();
        if bytes == 0 {
            bytes = buffer.len();
        }
    });
    b.bytes = bytes;
}

#[bench]
fn bench_signature_attributes_from_reader(b: &mut Bencher) {
    let mut attributes = SignatureAttributes::new();
    attributes.set_signature_data(Some(&[1, 2, 3]));
    attributes.set_payload_encoding(Some(123));
    attributes.set_scheme(Some(456));
    attributes.set_algorithm_name(Some("test-sig-algo"));
    attributes.set_nonce(Some(&[7, 8, 9]));
    attributes.set_public_key(Some(&[10, 11, 12]));

    let mut buffer = Vec::new();
    attributes.to_writer(&mut buffer).unwrap();

    b.iter(|| {
        let mut reader = std::io::Cursor::new(buffer.as_slice());
        let _ = black_box(SignatureAttributes::from_reader(&mut reader).unwrap());
    });
    b.bytes = buffer.len();
}
