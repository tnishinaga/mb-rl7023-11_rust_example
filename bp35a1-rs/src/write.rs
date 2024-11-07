pub trait ByteWrite: core::fmt::Write {
    fn byte_write(&mut self, data: &[u8]) -> Result<usize, core::fmt::Error>;
}
