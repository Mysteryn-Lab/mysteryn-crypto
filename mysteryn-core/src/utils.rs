#[macro_export]
/// Concatenates a series of byte slices into a vector.
///
/// This macro accepts zero or more arguments, where each argument implements `AsRef<&[u8]>`, and
/// efficiently combines their byte representations into a `Vec` in order of declaration.
macro_rules! concat_vec {
    () => { Vec::with_capacity(0) };
    ($($s:expr),+) => {{
        use std::ops::AddAssign;
        let mut len = 0;
        $(len.add_assign(AsRef::<[u8]>::as_ref(&$s).len());)+
        let mut buf = Vec::with_capacity(len);
        $(buf.extend_from_slice($s.as_ref());)+
        buf
    }};
}
