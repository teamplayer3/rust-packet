use std::{
    convert::TryInto,
    fmt::{self, Debug},
};

use crate::error::*;

use super::operations::{ARP_REQUEST, ARP_RESPONSE};

pub enum Packet<M, I, B> {
    Request(request::Packet<M, I, B>),
    Response(response::Packet<M, I, B>),
}

impl<M, I, B> crate::size::Min for Packet<M, I, B>
where
    B: AsRef<[u8]>,
    M: From<[u8; 6]> + Debug,
    I: From<[u8; 4]> + Debug,
{
    fn min() -> usize {
        28
    }
}

impl<M, I, B> crate::size::Max for Packet<M, I, B>
where
    B: AsRef<[u8]>,
    M: From<[u8; 6]> + Debug,
    I: From<[u8; 4]> + Debug,
{
    fn max() -> usize {
        28
    }
}

impl<M, I, B> crate::size::Size for Packet<M, I, B>
where
    B: AsRef<[u8]>,
    M: From<[u8; 6]> + Debug,
    I: From<[u8; 4]> + Debug,
{
    fn size(&self) -> usize {
        28
    }
}

impl<M, I, B> fmt::Debug for Packet<M, I, B>
where
    B: AsRef<[u8]>,
    M: From<[u8; 6]> + Debug,
    I: From<[u8; 4]> + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("arp::Packet")
            .field("operation", &self.operation())
            .finish()
    }
}

impl<M, I, B> Packet<M, I, B>
where
    B: AsRef<[u8]>,
    M: From<[u8; 6]> + Debug,
    I: From<[u8; 4]> + Debug,
{
    /// Create an ARP Request/Reply packet without checking the buffer.
    pub fn unchecked(buffer: B) -> Packet<M, I, B>
    where
        M: From<[u8; 6]> + Debug,
        I: From<[u8; 4]> + Debug,
    {
        let op = u16::from_be_bytes(buffer.as_ref()[6..8].try_into().unwrap());

        match op {
            ARP_REQUEST => Self::Request(request::Packet::unchecked(buffer)),
            ARP_RESPONSE => Self::Response(response::Packet::unchecked(buffer)),
            _ => panic!("arp operation not supported"),
        }
    }

    pub fn new(buffer: B) -> Result<Packet<M, I, B>>
    where
        M: From<[u8; 6]> + Debug,
        I: From<[u8; 4]> + Debug,
    {
        use crate::size::Min;

        let op = u16::from_be_bytes(buffer.as_ref()[6..8].try_into().unwrap());

        if buffer.as_ref().len() < Self::min() {
            Err(Error::SmallBuffer)?
        }

        match op {
            ARP_REQUEST => Ok(Self::Request(request::Packet::unchecked(buffer))),
            ARP_RESPONSE => Ok(Self::Response(response::Packet::unchecked(buffer))),
            _ => Err(Error::InvalidPacket),
        }
    }
}

impl<M, I, B> Packet<M, I, B>
where
    B: AsRef<[u8]>,
    M: From<[u8; 6]> + Debug,
    I: From<[u8; 4]> + Debug,
{
    fn operation(&self) -> &str {
        match *self {
            Packet::Request(_) => "Request",
            Packet::Response(_) => "Respnse",
        }
    }
}

pub mod request {
    use std::{
        convert::TryInto,
        fmt::{self, Debug, DebugStruct},
        marker::PhantomData,
    };

    pub struct Packet<M, I, B> {
        buffer: B,

        _phantom_mac: PhantomData<M>,
        _phantom_ip: PhantomData<I>,
    }

    impl<M, I, B> fmt::Debug for Packet<M, I, B>
    where
        B: AsRef<[u8]>,
        M: From<[u8; 6]> + Debug,
        I: From<[u8; 4]> + Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.debug_fmt(f.debug_struct("arp::request::Packet"))
        }
    }

    impl<M, I, B> Packet<M, I, B>
    where
        B: AsRef<[u8]>,
        M: From<[u8; 6]> + Debug,
        I: From<[u8; 4]> + Debug,
    {
        pub(crate) fn unchecked(buffer: B) -> Self {
            Self {
                buffer,
                _phantom_ip: PhantomData::default(),
                _phantom_mac: PhantomData::default(),
            }
        }
    }

    impl<M, I, B: AsRef<[u8]>> Packet<M, I, B>
    where
        M: From<[u8; 6]> + Debug,
        I: From<[u8; 4]> + Debug,
    {
        fn debug_fmt(&self, mut db_struct: DebugStruct) -> fmt::Result {
            db_struct
                .field("src_mac", &self.source_mac())
                .field("src_ip", &self.source_ip())
                .field("requested_ip", &self.ip_to_find())
                .finish()
        }

        pub fn source_mac(&self) -> M {
            M::from(self.buffer.as_ref()[8..14].try_into().unwrap())
        }

        pub fn source_ip(&self) -> I {
            I::from(self.buffer.as_ref()[14..18].try_into().unwrap())
        }

        pub fn ip_to_find(&self) -> I {
            I::from(self.buffer.as_ref()[24..28].try_into().unwrap())
        }
    }
}

pub mod response {
    use std::{
        convert::TryInto,
        fmt::{self, Debug, DebugStruct},
        marker::PhantomData,
    };

    pub struct Packet<M, I, B> {
        buffer: B,

        _phantom_mac: PhantomData<M>,
        _phantom_ip: PhantomData<I>,
    }

    impl<M, I, B> fmt::Debug for Packet<M, I, B>
    where
        B: AsRef<[u8]>,
        M: From<[u8; 6]> + Debug,
        I: From<[u8; 4]> + Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.debug_fmt(f.debug_struct("arp::response::Packet"))
        }
    }

    impl<M, I, B> Packet<M, I, B>
    where
        B: AsRef<[u8]>,
        M: From<[u8; 6]> + Debug,
        I: From<[u8; 4]> + Debug,
    {
        pub(crate) fn unchecked(buffer: B) -> Self {
            Self {
                buffer,
                _phantom_ip: PhantomData::default(),
                _phantom_mac: PhantomData::default(),
            }
        }
    }

    impl<M, I, B> Packet<M, I, B>
    where
        B: AsRef<[u8]>,
        M: From<[u8; 6]> + Debug,
        I: From<[u8; 4]> + Debug,
    {
        fn debug_fmt(&self, mut db_struct: DebugStruct) -> fmt::Result {
            db_struct
                .field("src_mac", &self.source_mac())
                .field("dest_mac", &self.destination_mac())
                .field("src_ip", &self.source_ip())
                .field("dest_ip", &self.destination_ip())
                .finish()
        }

        pub fn source_mac(&self) -> M {
            M::from(self.buffer.as_ref()[8..14].try_into().unwrap())
        }

        pub fn destination_mac(&self) -> M {
            M::from(self.buffer.as_ref()[18..24].try_into().unwrap())
        }

        pub fn source_ip(&self) -> I {
            I::from(self.buffer.as_ref()[14..18].try_into().unwrap())
        }

        pub fn destination_ip(&self) -> I {
            I::from(self.buffer.as_ref()[24..28].try_into().unwrap())
        }
    }
}
