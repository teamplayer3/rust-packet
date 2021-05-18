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
    pub fn request(self) -> Result<operations::request::Builder<B>> {
        let mut request = operations::request::Builder::with(self.buffer)?;
        request.finalizer().extend(self.finalizer);

        Ok(request)
    }

    // Create an IPv6 packet.
    // pub fn response(self) -> Result<v6::Builder<B>> {
    //     let mut v6 = v6::Builder::with(self.buffer)?;
    //     v6.finalizer().extend(self.finalizer);

    //     Ok(v6)
    // }
}
