use byteorder::{BigEndian, WriteBytesExt};
use util::{Address, IPAddr, IPAddrType, MACAddr, MACAddrType};

use crate::buffer::Buffer;
use crate::error::*;

const ARP_REQUEST: u16 = 0x0001;
const ARP_RESPONSE: u16 = 0x0002;

#[allow(unreachable_patterns)]
fn mac_addr_type_to_bytes(addr_type: MACAddrType) -> u16 {
    use MACAddrType::*;
    match addr_type {
        Ethernet => 0x0001,
        _ => 0,
    }
}

#[allow(unreachable_patterns)]
fn ip_addr_type_to_bytes(addr_type: IPAddrType) -> u16 {
    use IPAddrType::*;
    match addr_type {
        IPv4 => 0x0800,
        _ => 0,
    }
}

fn set_ip_addr_info<B, I>(buffer: &mut B, addr: &I, prev_addr_len: &mut usize) -> Result<()>
where
    B: Buffer,
    I: Address + IPAddr,
{
    let len = addr.len();
    if *prev_addr_len == 0 {
        let addr_type = ip_addr_type_to_bytes(addr.addr_type());
        set_ip_addr_type(buffer, addr_type)?;
        set_ip_addr_len(buffer, len);

        *prev_addr_len = len
    } else {
        assert_eq!(len, *prev_addr_len, "IP address length must be consistent.");
    }

    Ok(())
}

fn set_mac_addr_info<B, M>(buffer: &mut B, addr: &M, prev_addr_len: &mut usize) -> Result<()>
where
    B: Buffer,
    M: Address + MACAddr,
{
    let len = addr.len();
    if *prev_addr_len == 0 {
        let addr_type = mac_addr_type_to_bytes(addr.addr_type());
        set_mac_addr_type(buffer, addr_type)?;
        set_mac_addr_len(buffer, len);

        *prev_addr_len = len
    } else {
        assert_eq!(
            len, *prev_addr_len,
            "MAC address length must be consistent."
        );
    }

    Ok(())
}

fn set_mac_addr_type<B: Buffer>(buffer: &mut B, addr_type: u16) -> Result<()> {
    std::io::Cursor::new(&mut buffer.data_mut()[..2])
        .write_u16::<BigEndian>(addr_type)
        .map_err(|e| e.into())
}

fn set_ip_addr_type<B: Buffer>(buffer: &mut B, addr_type: u16) -> Result<()> {
    std::io::Cursor::new(&mut buffer.data_mut()[2..4])
        .write_u16::<BigEndian>(addr_type)
        .map_err(|e| e.into())
}

fn set_ip_addr_len<B: Buffer>(buffer: &mut B, len: usize) {
    assert!(len <= 4, "IP address must have 4 or less octets.");
    buffer.data_mut()[5] = len as u8;
}

fn set_mac_addr_len<B: Buffer>(buffer: &mut B, len: usize) {
    assert!(len <= 6, "MAC address must have 6 or less octets.");
    buffer.data_mut()[4] = len as u8;
}

pub mod request {
    use std::{marker::PhantomData, usize};

    use byteorder::{BigEndian, WriteBytesExt};
    use util::{Address, IPAddr, MACAddr};

    use crate::buffer::{self, Buffer};
    use crate::builder::{Builder as Build, Finalization};
    use crate::error::*;

    use super::{set_ip_addr_info, set_mac_addr_info};

    #[derive(Debug)]
    pub struct Builder<M, I, B: Buffer = buffer::Dynamic>
    where
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        buffer: B,
        finalizer: Finalization,

        ip_address_len: usize,
        mac_address_len: usize,

        src: bool,
        dest: bool,

        _phantom_mac: PhantomData<M>,
        _phantom_ip: PhantomData<I>,
    }

    impl<M, I, B> Build<B> for Builder<M, I, B>
    where
        B: Buffer,
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        fn with(mut buffer: B) -> Result<Self> {
            buffer.next(28)?;

            // dest mac as 0x00 .. 0x00 address
            buffer.data_mut()[18..24].fill(0);
            // set request operation -> 0x01
            std::io::Cursor::new(&mut buffer.data_mut()[6..8])
                .write_u16::<BigEndian>(super::ARP_REQUEST)?;

            Ok(Builder {
                buffer: buffer,
                finalizer: Default::default(),

                ip_address_len: 0,
                mac_address_len: 0,

                src: false,
                dest: false,

                _phantom_mac: PhantomData::default(),
                _phantom_ip: PhantomData::default(),
            })
        }

        fn finalizer(&mut self) -> &mut Finalization {
            &mut self.finalizer
        }

        fn build(self) -> Result<B::Inner> {
            if !self.src || !self.dest {
                Err(Error::InvalidPacket)?
            }

            let mut buffer = self.buffer.into_inner();
            self.finalizer.finalize(buffer.as_mut())?;
            Ok(buffer)
        }
    }

    impl<M, I> Default for Builder<M, I, buffer::Dynamic>
    where
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        fn default() -> Self {
            Builder::<M, I, buffer::Dynamic>::with(buffer::Dynamic::default()).unwrap()
        }
    }

    impl<M, I, B> Builder<M, I, B>
    where
        B: Buffer,
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        /// IP to find the mac for.
        pub fn ip_to_find(mut self, ip: I) -> Result<Self> {
            let addr_len = ip.len();
            set_ip_addr_info(&mut self.buffer, &ip, &mut self.ip_address_len)?;

            self.buffer.data_mut()[24..24 + addr_len].clone_from_slice(ip.octets().as_slice());

            self.dest = true;
            Ok(self)
        }

        /// Source mac and ip.
        pub fn source(mut self, mac: M, ip: I) -> Result<Self> {
            // ------- set src mac
            let addr_len = mac.len();
            set_mac_addr_info(&mut self.buffer, &mac, &mut self.mac_address_len)?;

            self.buffer.data_mut()[8..8 + addr_len].clone_from_slice(mac.octets().as_slice());

            // ------- set src ip
            let addr_len = ip.len();
            set_ip_addr_info(&mut self.buffer, &ip, &mut self.ip_address_len)?;
            self.buffer.data_mut()[14..14 + addr_len].clone_from_slice(ip.octets().as_slice());

            self.src = true;
            Ok(self)
        }
    }
}

pub mod response {
    use std::{marker::PhantomData, usize};

    use byteorder::{BigEndian, WriteBytesExt};
    use util::{Address, IPAddr, MACAddr};

    use crate::buffer::{self, Buffer};
    use crate::builder::{Builder as Build, Finalization};
    use crate::error::*;

    use super::{set_ip_addr_info, set_mac_addr_info};

    #[derive(Debug)]
    pub struct Builder<M, I, B: Buffer = buffer::Dynamic>
    where
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        buffer: B,
        finalizer: Finalization,

        ip_address_len: usize,
        mac_address_len: usize,

        src: bool,
        dest: bool,

        _phantom_mac: PhantomData<M>,
        _phantom_ip: PhantomData<I>,
    }

    impl<M, I, B> Build<B> for Builder<M, I, B>
    where
        B: Buffer,
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        fn with(mut buffer: B) -> Result<Self> {
            buffer.next(28)?;

            // set request operation -> 0x01
            std::io::Cursor::new(&mut buffer.data_mut()[6..8])
                .write_u16::<BigEndian>(super::ARP_RESPONSE)?;

            Ok(Builder {
                buffer: buffer,
                finalizer: Default::default(),

                ip_address_len: 0,
                mac_address_len: 0,

                src: false,
                dest: false,

                _phantom_mac: PhantomData::default(),
                _phantom_ip: PhantomData::default(),
            })
        }

        fn finalizer(&mut self) -> &mut Finalization {
            &mut self.finalizer
        }

        fn build(self) -> Result<B::Inner> {
            if !self.src || !self.dest {
                Err(Error::InvalidPacket)?
            }

            let mut buffer = self.buffer.into_inner();
            self.finalizer.finalize(buffer.as_mut())?;
            Ok(buffer)
        }
    }

    impl<M, I> Default for Builder<M, I, buffer::Dynamic>
    where
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        fn default() -> Self {
            Builder::<M, I, buffer::Dynamic>::with(buffer::Dynamic::default()).unwrap()
        }
    }

    impl<M, I, B> Builder<M, I, B>
    where
        B: Buffer,
        M: Address + MACAddr,
        I: Address + IPAddr,
    {
        /// Destination mac and ip.
        pub fn destination(mut self, mac: M, ip: I) -> Result<Self> {
            // ------- set src mac
            let addr_len = mac.len();
            set_mac_addr_info(&mut self.buffer, &mac, &mut self.mac_address_len)?;

            self.buffer.data_mut()[18..18 + addr_len].clone_from_slice(mac.octets().as_slice());

            // ------- set src ip
            let addr_len = ip.len();
            set_ip_addr_info(&mut self.buffer, &ip, &mut self.ip_address_len)?;
            self.buffer.data_mut()[24..24 + addr_len].clone_from_slice(ip.octets().as_slice());

            self.dest = true;
            Ok(self)
        }

        /// Source mac and ip.
        pub fn source(mut self, mac: M, ip: I) -> Result<Self> {
            // ------- set src mac
            let addr_len = mac.len();
            set_mac_addr_info(&mut self.buffer, &mac, &mut self.mac_address_len)?;

            self.buffer.data_mut()[8..8 + addr_len].clone_from_slice(mac.octets().as_slice());

            // ------- set src ip
            let addr_len = ip.len();
            set_ip_addr_info(&mut self.buffer, &ip, &mut self.ip_address_len)?;
            self.buffer.data_mut()[14..14 + addr_len].clone_from_slice(ip.octets().as_slice());

            self.src = true;
            Ok(self)
        }
    }
}
