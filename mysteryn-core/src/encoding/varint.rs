use std::io::{Error, ErrorKind, Read, Result, Write};

/// Read a varint `usize` from the provided reader.
/// Returns `Ok(None)` on unexpected `EOF`.
pub fn read_varint_usize<R: Read + Unpin>(reader: &mut R) -> Result<Option<usize>> {
    let mut b = unsigned_varint::encode::usize_buffer();
    for i in 0..b.len() {
        let n = reader.read(&mut b[i..=i])?;
        if n == 0 {
            return Ok(None);
        }
        if unsigned_varint::decode::is_last(b[i]) {
            let slice = &b[..=i];
            let (num, _) = unsigned_varint::decode::usize(slice)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid varint"))?;
            return Ok(Some(num));
        }
    }
    Err(Error::new(ErrorKind::InvalidInput, "varint overflow"))
}

/// Write a varint `usize` to the provided writer.
/// Returns the number of bytes written.
pub fn write_varint_usize<W: Write + Unpin>(num: usize, writer: &mut W) -> Result<usize> {
    let mut buffer = unsigned_varint::encode::usize_buffer();
    let to_write = unsigned_varint::encode::usize(num, &mut buffer);
    writer.write_all(to_write)?;
    Ok(to_write.len())
}

/// Write a varint `usize` to the provided writer, expecting the writer cannot fail.
/// Returns the number of bytes written.
pub fn write_varint_usize_unsafe<W: Write + Unpin>(num: usize, writer: &mut W) -> usize {
    #[expect(clippy::missing_panics_doc, reason = "writer is already checked")]
    write_varint_usize(num, writer).unwrap()
}

/// Read a varint `u64` from the provided reader. Returns `Ok(None)` on unexpected `EOF`.
pub fn read_varint_u64<R: Read + Unpin>(reader: &mut R) -> Result<Option<u64>> {
    let mut b = unsigned_varint::encode::u64_buffer();
    for i in 0..b.len() {
        let n = reader.read(&mut b[i..=i])?;
        if n == 0 {
            return Ok(None);
        }
        if unsigned_varint::decode::is_last(b[i]) {
            let slice = &b[..=i];
            let (num, _) = unsigned_varint::decode::u64(slice)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid varint"))?;
            return Ok(Some(num));
        }
    }
    Err(Error::new(ErrorKind::InvalidInput, "varint overflow"))
}

/// Write a varint `u64` to the provided writer. Returns the number of bytes written.
pub fn write_varint_u64<W: Write + Unpin>(num: u64, writer: &mut W) -> Result<usize> {
    let mut buffer = unsigned_varint::encode::u64_buffer();
    let to_write = unsigned_varint::encode::u64(num, &mut buffer);
    writer.write_all(to_write)?;

    Ok(to_write.len())
}

/// Write a varint `u64` to the provided writer, expecting the writer cannot fail.
/// Returns the number of bytes written.
pub fn write_varint_u64_unsafe<W: Write + Unpin>(num: u64, writer: &mut W) -> usize {
    #[expect(clippy::missing_panics_doc, reason = "writer is already checked")]
    write_varint_u64(num, writer).unwrap()
}

/// Encode an `usize` to varint.
pub fn encode_varint_usize(num: usize) -> Vec<u8> {
    let mut buffer = unsigned_varint::encode::usize_buffer();
    let to_write = unsigned_varint::encode::usize(num, &mut buffer);
    to_write.to_vec()
}

/// Decode an `usize` from varint.
pub fn decode_varint_usize(buf: &[u8]) -> Result<usize> {
    let r = unsigned_varint::decode::usize(buf)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid varint"))?;
    Ok(r.0)
}

/// Encode an `u64` to varint.
pub fn encode_varint_u64(num: u64) -> Vec<u8> {
    let mut buffer = unsigned_varint::encode::u64_buffer();
    let to_write = unsigned_varint::encode::u64(num, &mut buffer);
    to_write.to_vec()
}

/// Decode an `u64` from varint.
pub fn decode_varint_u64(buf: &[u8]) -> Result<u64> {
    let r = unsigned_varint::decode::u64(buf)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid varint"))?;
    Ok(r.0)
}

/// Read `varbytes` from the provided reader.
/// Prefer the non-allocating `decode_varbytes` when possible.
pub fn read_varbytes<R: Read + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let size = read_varint_usize(reader)
        .map_err(|e| Error::other(e.to_string()))?
        .ok_or_else(|| Error::from(ErrorKind::UnexpectedEof))?;
    if size == 0 {
        return Ok(vec![]);
    }
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write `varbytes` to the provided writer. Returns the number of bytes written.
pub fn write_varbytes<W: Write + Unpin>(bytes: &[u8], writer: &mut W) -> Result<usize> {
    let mut buffer = unsigned_varint::encode::usize_buffer();
    let len_buf = unsigned_varint::encode::usize(bytes.len(), &mut buffer);
    writer.write_all(len_buf)?;
    // No intermediate copy - just write the payload directly.
    writer.write_all(bytes)?;
    Ok(len_buf.len() + bytes.len())
}

/// Write `varbytes` to the provided writer, expecting the writer cannot fail.
/// Returns the number of bytes written.
pub fn write_varbytes_unsafe<W: Write + Unpin>(bytes: &[u8], writer: &mut W) -> usize {
    #[expect(clippy::missing_panics_doc, reason = "writer is already checked")]
    write_varbytes(bytes, writer).unwrap()
}

/// Encode bytes to `varbytes`.
pub fn encode_varbytes(bytes: &[u8]) -> Vec<u8> {
    let mut buffer = unsigned_varint::encode::usize_buffer();
    let len_buf = unsigned_varint::encode::usize(bytes.len(), &mut buffer);
    let mut buf = Vec::with_capacity(len_buf.len() + bytes.len());
    buf.extend(len_buf);
    buf.extend(bytes);
    buf
}

/// Decode bytes from `varbytes`.
/// Returns a tuple with the decoded bytes and the rest.
pub fn decode_varbytes(varbytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let (len, bytes) = unsigned_varint::decode::usize(varbytes)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid varbytes"))?;
    Ok((&bytes[..len], &bytes[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_varint_usize() {
        let numbers = [0, 1, 127, 128, 255, 256, 16383, 16384, usize::MAX];
        for &num in &numbers {
            let mut buffer = Vec::new();
            let written = write_varint_usize(num, &mut buffer).unwrap();
            assert_eq!(written, encode_varint_usize(num).len());
            let mut reader = std::io::Cursor::new(buffer);
            let decoded = read_varint_usize(&mut reader).unwrap().unwrap();
            assert_eq!(num, decoded);
        }
    }

    #[test]
    fn test_read_varint_usize_eof() {
        let mut reader = std::io::Cursor::new(&[]);
        assert_eq!(read_varint_usize(&mut reader).unwrap(), None);
    }

    #[test]
    fn test_read_varint_usize_invalid() {
        let mut reader = std::io::Cursor::new(&[
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ]);
        assert!(read_varint_usize(&mut reader).is_err());
    }

    #[test]
    fn test_read_write_varint_u64() {
        let numbers = [0, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX];
        for &num in &numbers {
            let mut buffer = Vec::new();
            let written = write_varint_u64(num, &mut buffer).unwrap();
            assert_eq!(written, encode_varint_u64(num).len());
            let mut reader = std::io::Cursor::new(buffer);
            let decoded = read_varint_u64(&mut reader).unwrap().unwrap();
            assert_eq!(num, decoded);
        }
    }

    #[test]
    fn test_read_varint_u64_eof() {
        let mut reader = std::io::Cursor::new(&[]);
        assert_eq!(read_varint_u64(&mut reader).unwrap(), None);
    }

    #[test]
    fn test_read_varint_u64_invalid() {
        let mut reader = std::io::Cursor::new(&[
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ]);
        assert!(read_varint_u64(&mut reader).is_err());
    }

    #[test]
    fn test_encode_decode_varint_usize() {
        let numbers = [0, 1, 127, 128, 255, 256, 16383, 16384, usize::MAX];
        for &num in &numbers {
            let encoded = encode_varint_usize(num);
            let decoded = decode_varint_usize(&encoded).unwrap();
            assert_eq!(num, decoded);
        }
    }

    #[test]
    fn test_encode_decode_varint_u64() {
        let numbers = [0, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX];
        for &num in &numbers {
            let encoded = encode_varint_u64(num);
            let decoded = decode_varint_u64(&encoded).unwrap();
            assert_eq!(num, decoded);
        }
    }

    #[test]
    fn test_read_write_varbytes() {
        let data = [vec![], vec![1, 2, 3], vec![0; 1024]];
        for bytes in &data {
            let mut buffer = Vec::new();
            let written = write_varbytes(bytes, &mut buffer).unwrap();
            assert_eq!(written, encode_varbytes(bytes).len());
            let mut reader = std::io::Cursor::new(buffer);
            let decoded = read_varbytes(&mut reader).unwrap();
            assert_eq!(bytes, &decoded);
        }
    }

    #[test]
    fn test_read_varbytes_eof() {
        let mut reader = std::io::Cursor::new(&[]);
        assert!(matches!(
            read_varbytes(&mut reader).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn test_encode_decode_varbytes() {
        let data = [vec![], vec![1, 2, 3], vec![0; 1024]];
        for bytes in &data {
            let encoded = encode_varbytes(bytes);
            let (decoded, rest) = decode_varbytes(&encoded).unwrap();
            assert_eq!(bytes, decoded);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_write_varint_usize_unsafe() {
        let num = 12345;
        let mut buffer = Vec::new();
        let written = write_varint_usize_unsafe(num, &mut buffer);
        assert_eq!(written, encode_varint_usize(num).len());
        let mut reader = std::io::Cursor::new(buffer);
        let decoded = read_varint_usize(&mut reader).unwrap().unwrap();
        assert_eq!(num, decoded);
    }

    #[test]
    fn test_write_varint_u64_unsafe() {
        let num = 1234567890;
        let mut buffer = Vec::new();
        let written = write_varint_u64_unsafe(num, &mut buffer);
        assert_eq!(written, encode_varint_u64(num).len());
        let mut reader = std::io::Cursor::new(buffer);
        let decoded = read_varint_u64(&mut reader).unwrap().unwrap();
        assert_eq!(num, decoded);
    }

    #[test]
    fn test_write_varbytes_unsafe() {
        let bytes = &[1, 2, 3, 4, 5];
        let mut buffer = Vec::new();
        let written = write_varbytes_unsafe(bytes, &mut buffer);
        assert_eq!(written, encode_varbytes(bytes).len());
        let mut reader = std::io::Cursor::new(buffer);
        let decoded = read_varbytes(&mut reader).unwrap();
        assert_eq!(bytes, decoded.as_slice());
    }
}
