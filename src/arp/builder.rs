use util::{Address, IPAddr, MACAddr};

use crate::{
    buffer::{self, Buffer},
    builder::{Builder as Build, Finalization},
    error::*,
};

use super::operations;

pub struct Builder<B: Buffer = buffer::Dynamic> {
    buffer: B,
    finalizer: Finalization,
}

impl<B: Buffer> Build<B> for Builder<B> {
    fn with(buffer: B) -> Result<Self> {
        Ok(Builder {
            buffer: buffer,
            finalizer: Default::default(),
        })
    }

    fn finalizer(&mut self) -> &mut Finalization {
        &mut self.finalizer
    }

    fn build(self) -> Result<B::Inner> {
        Err(Error::InvalidPacket)
    }
}

impl Default for Builder<buffer::Dynamic> {
    fn default() -> Self {
        Builder::with(buffer::Dynamic::default()).unwrap()
    }
}

impl<B: Buffer> Builder<B> {
    /// Create an arp request packet.
    pub fn request<M, I>(self) -> Result<operations::request::Builder<M, I, B>>
    where
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        let mut request = operations::request::Builder::<M, I, B>::with(self.buffer)?;
        request.finalizer().extend(self.finalizer);

        Ok(request)
    }

    /// Create an arp response packet.
    pub fn response<M, I>(self) -> Result<operations::response::Builder<M, I, B>>
    where
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        let mut request = operations::response::Builder::<M, I, B>::with(self.buffer)?;
        request.finalizer().extend(self.finalizer);

        Ok(request)
    }
}
