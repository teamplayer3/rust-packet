#[cfg(test)]
mod test {
    use std::{assert_matches::assert_matches, convert::TryInto, net::Ipv4Addr};

    use super::super::*;
    use crate::error::*;
    use util::MacAddr;

    #[test]
    fn create_request_packet() {
        use crate::Builder;
        let buffer = crate::buffer::Dynamic::new();

        let source_mac = MacAddr::from([0x23, 0x23, 0x25, 0x53, 0x23, 0x94]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 3);
        let to_find = Ipv4Addr::new(192, 168, 1, 4);

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

        let source_mac = MacAddr::from([0x23, 0x23, 0x25, 0x53, 0x23, 0x94]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 3);
        let dest_mac = MacAddr::from([0x87, 0x23, 0x25, 0x10, 0x23, 0x94]);
        let dest_ip = Ipv4Addr::new(192, 168, 1, 4);

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

    #[test]
    fn from_request_packet() {
        use packet::Packet;
        let bytes = [
            0u8, 1, 8, 0, 6, 4, 0, 1, 35, 35, 37, 83, 35, 148, 192, 168, 1, 3, 0, 0, 0, 0, 0, 0,
            192, 168, 1, 4,
        ];

        let source_mac = MacAddr::from([0x23, 0x23, 0x25, 0x53, 0x23, 0x94]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 3);
        let to_find = Ipv4Addr::new(192, 168, 1, 4);

        let packet = Packet::<MacAddr, Ipv4Addr, _>::unchecked(bytes);
        assert_matches!(packet, Packet::Request(_));

        if let Packet::Request(p) = packet {
            assert_eq!(p.source_mac(), source_mac);
            assert_eq!(p.source_ip(), source_ip);
            assert_eq!(p.ip_to_find(), to_find);
        }
    }

    #[test]
    fn from_response_packet() {
        use packet::Packet;
        let bytes = [
            0u8, 1, 8, 0, 6, 4, 0, 2, 35, 35, 37, 83, 35, 148, 192, 168, 1, 3, 135, 35, 37, 16, 35,
            148, 192, 168, 1, 4,
        ];

        let source_mac = MacAddr::from([0x23, 0x23, 0x25, 0x53, 0x23, 0x94]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 3);
        let dest_mac = MacAddr::from([0x87, 0x23, 0x25, 0x10, 0x23, 0x94]);
        let dest_ip = Ipv4Addr::new(192, 168, 1, 4);

        let packet = Packet::<MacAddr, Ipv4Addr, _>::unchecked(bytes);
        assert_matches!(packet, Packet::Response(_));

        if let Packet::Response(p) = packet {
            assert_eq!(p.source_mac(), source_mac);
            assert_eq!(p.source_ip(), source_ip);
            assert_eq!(p.destination_mac(), dest_mac);
            assert_eq!(p.destination_ip(), dest_ip);
        }
    }
}
