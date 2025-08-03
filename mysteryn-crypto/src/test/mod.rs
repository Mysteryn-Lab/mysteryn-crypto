use serde::{Serialize, de::DeserializeOwned};
use serde_ipld_dagcbor::{from_slice, to_vec};

pub fn dag_cbor_roundtrip<T>(data: &T) -> crate::result::Result<T>
where
    T: Serialize + DeserializeOwned,
{
    Ok(
        from_slice(&to_vec(data).map_err(|e| crate::result::Error::EncodingError(e.to_string()))?)
            .map_err(|e| crate::result::Error::EncodingError(e.to_string()))?,
    )
}
