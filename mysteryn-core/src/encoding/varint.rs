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
