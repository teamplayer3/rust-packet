use util::{IPAddrType, MACAddrType};

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

pub mod request {
    use std::{ops::Add, usize};

    use byteorder::{BigEndian, WriteBytesExt};
    use util::{Address, IPAddr, IPv4Addr, MACAddr};

    use crate::buffer::{self, Buffer};
    use crate::builder::{Builder as Build, Finalization};
    use crate::error::*;

    #[derive(Debug)]
    pub struct Builder<B: Buffer = buffer::Dynamic> {
        buffer: B,
        finalizer: Finalization,

        ip_address_len: usize,
        mac_address_len: usize,
    }

    impl<B> Build<B> for Builder<B>
    where
        B: Buffer,
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
            })
        }

        fn finalizer(&mut self) -> &mut Finalization {
            &mut self.finalizer
        }

        fn build(self) -> Result<B::Inner> {
            if self.ip_address_len == 0 || self.mac_address_len == 0 {
                Err(Error::InvalidPacket)?
            }

            let mut buffer = self.buffer.into_inner();
            self.finalizer.finalize(buffer.as_mut())?;
            Ok(buffer)
        }
    }

    impl Default for Builder<buffer::Dynamic> {
        fn default() -> Self {
            Builder::with(buffer::Dynamic::default()).unwrap()
        }
    }

    impl<B> Builder<B>
    where
        B: Buffer,
    {
        /// IP to find the mac for.
        pub fn ip_to_find<T>(mut self, address: T) -> Result<Self>
        where
            T: Address + IPAddr,
        {
            let addr_len = address.len();
            self.set_ip_addr_len(addr_len);

            self.buffer.data_mut()[24..24 + addr_len].clone_from_slice(address.octets().as_slice());

            Ok(self)
        }

        /// Source mac and ip.
        pub fn source<T, I>(mut self, mac: T, ip: I) -> Result<Self>
        where
            T: Address + MACAddr,
            I: Address + IPAddr,
        {
            // ------- set src mac
            let addr_len = mac.len();
            self.set_mac_addr_info(&mac)?;

            self.buffer.data_mut()[8..8 + addr_len].clone_from_slice(mac.octets().as_slice());

            // ------- set src ip
            let addr_len = ip.len();
            self.set_ip_addr_info(&ip)?;
            self.buffer.data_mut()[14..14 + addr_len].clone_from_slice(ip.octets().as_slice());

            Ok(self)
        }

        fn set_ip_addr_info<T>(&mut self, addr: &T) -> Result<()>
        where
            T: Address + IPAddr,
        {
            let len = addr.len();
            if self.ip_address_len == 0 {
                let addr_type = super::ip_addr_type_to_bytes(addr.addr_type());
                self.set_ip_addr_type(addr_type)?;
                self.set_ip_addr_len(len);

                self.ip_address_len = len
            } else {
                assert_eq!(
                    len, self.ip_address_len,
                    "IP address length must be consistent."
                );
            }

            Ok(())
        }

        fn set_mac_addr_info<T>(&mut self, addr: &T) -> Result<()>
        where
            T: Address + MACAddr,
        {
            let len = addr.len();
            if self.mac_address_len == 0 {
                let addr_type = super::mac_addr_type_to_bytes(addr.addr_type());
                self.set_mac_addr_type(addr_type)?;
                self.set_mac_addr_len(len);

                self.mac_address_len = len
            } else {
                assert_eq!(
                    len, self.mac_address_len,
                    "MAC address length must be consistent."
                );
            }

            Ok(())
        }

        fn set_mac_addr_type(&mut self, addr_type: u16) -> Result<()> {
            std::io::Cursor::new(&mut self.buffer.data_mut()[..2])
                .write_u16::<BigEndian>(addr_type)
                .map_err(|e| e.into())
        }

        fn set_ip_addr_type(&mut self, addr_type: u16) -> Result<()> {
            std::io::Cursor::new(&mut self.buffer.data_mut()[2..4])
                .write_u16::<BigEndian>(addr_type)
                .map_err(|e| e.into())
        }

        fn set_ip_addr_len(&mut self, len: usize) {
            assert!(len <= 4, "IP address must have 4 or less octets.");
            self.buffer.data_mut()[5] = len as u8;
        }

        fn set_mac_addr_len(&mut self, len: usize) {
            assert!(len <= 6, "MAC address must have 6 or less octets.");
            self.buffer.data_mut()[4] = len as u8;
        }
    }
}

pub mod response {
    use std::usize;

    use byteorder::{BigEndian, WriteBytesExt};
    use util::{Address, IPAddr, MACAddr};

    use crate::buffer::{self, Buffer};
    use crate::builder::{Builder as Build, Finalization};
    use crate::error::*;

    #[derive(Debug)]
    pub struct Builder<B: Buffer = buffer::Dynamic> {
        buffer: B,
        finalizer: Finalization,

        ip_address_len: usize,
        mac_address_len: usize,
    }

    impl<B> Build<B> for Builder<B>
    where
        B: Buffer,
    {
        fn with(mut buffer: B) -> Result<Self> {
            buffer.next(28)?;

            // set response operation -> 0x02
            std::io::Cursor::new(&mut buffer.data_mut()[6..8])
                .write_u16::<BigEndian>(super::ARP_RESPONSE)?;

            Ok(Builder {
                buffer: buffer,
                finalizer: Default::default(),

                ip_address_len: 0,
                mac_address_len: 0,
            })
        }

        fn finalizer(&mut self) -> &mut Finalization {
            &mut self.finalizer
        }

        fn build(self) -> Result<B::Inner> {
            if self.ip_address_len == 0 || self.mac_address_len == 0 {
                Err(Error::InvalidPacket)?
            }

            let mut buffer = self.buffer.into_inner();
            self.finalizer.finalize(buffer.as_mut())?;
            Ok(buffer)
        }
    }

    impl Default for Builder<buffer::Dynamic> {
        fn default() -> Self {
            Builder::with(buffer::Dynamic::default()).unwrap()
        }
    }
}
