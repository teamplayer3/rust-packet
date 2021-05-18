#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use super::super::*;
    use crate::error::*;
    use util::{IPv4Addr, MacAddr};

    #[test]
    fn create_request_packet() {
        use crate::Builder;
        let buffer = crate::buffer::Dynamic::new();

        let source_mac = MacAddr::new(0x23, 0x23, 0x25, 0x53, 0x23, 0x94);
        let source_ip = IPv4Addr::new(192, 168, 1, 3);
        let to_find = IPv4Addr::new(192, 168, 1, 4);

        let build_packet = || -> Result<Vec<u8>> {
            Ok(builder::Builder::with(buffer)?
                .request()?
                .source(source_mac.to_owned(), source_ip.to_owned())?
                .ip_to_find(to_find.to_owned())?
                .build()?)
        };

        let packet = build_packet();
        assert_matches!(packet, Ok(_));

        let packet = packet.unwrap();

        assert_eq!(u16::from_be_bytes(packet[..2].try_into().unwrap()), 0x0001); // Ethernet
        assert_eq!(u16::from_be_bytes(packet[2..4].try_into().unwrap()), 0x0800); // IPv4

        assert_eq!(packet[4], 0x06); // mac len
        assert_eq!(packet[5], 0x04); // ipv4 len

        assert_eq!(u16::from_be_bytes(packet[6..8].try_into().unwrap()), 0x0001); // operation request

        assert_eq!(packet[8..14], source_mac.octets());
        assert_eq!(packet[14..18], source_ip.octets());

        assert_eq!(packet[18..24], [0, 0, 0, 0, 0, 0]);
        assert_eq!(packet[24..28], to_find.octets());
    }

    #[test]
    fn create_response_packet() {
        use crate::Builder;
        let buffer = crate::buffer::Dynamic::new();

        let source_mac = MacAddr::new(0x23, 0x23, 0x25, 0x53, 0x23, 0x94);
        let source_ip = IPv4Addr::new(192, 168, 1, 3);
        let dest_mac = MacAddr::new(0x87, 0x23, 0x25, 0x10, 0x23, 0x94);
        let dest_ip = IPv4Addr::new(192, 168, 1, 4);

        let build_packet = || -> Result<Vec<u8>> {
            Ok(builder::Builder::with(buffer)?
                .response()?
                .source(source_mac.to_owned(), source_ip.to_owned())?
                .destination(dest_mac.to_owned(), dest_ip.to_owned())?
                .build()?)
        };

        let packet = build_packet();
        assert_matches!(packet, Ok(_));

        let packet = packet.unwrap();

        assert_eq!(u16::from_be_bytes(packet[..2].try_into().unwrap()), 0x0001); // Ethernet
        assert_eq!(u16::from_be_bytes(packet[2..4].try_into().unwrap()), 0x0800); // IPv4

        assert_eq!(packet[4], 0x06); // mac len
        assert_eq!(packet[5], 0x04); // ipv4 len

        assert_eq!(u16::from_be_bytes(packet[6..8].try_into().unwrap()), 0x0002); // operation request

        assert_eq!(packet[8..14], source_mac.octets());
        assert_eq!(packet[14..18], source_ip.octets());

        assert_eq!(packet[18..24], dest_mac.octets());
        assert_eq!(packet[24..28], dest_ip.octets());
    }
}
