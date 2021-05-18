enum DataLink {
    ///
    Ethernet,

    ///
    Unknown(u16),
}

impl From<u16> for DataLink {
    fn from(value: u16) -> Self {
        use self::DataLink::*;

        match value {
            0x0001 => Ethernet,
            v => Unknown(v),
        }
    }
}

impl Into<(u16, u8)> for DataLink {
    fn into(self) -> (u16, u8) {
        use self::DataLink::*;

        match self {
            Ethernet => (0x0001, 6),
            Unknown(v) => (v, 0),
        }
    }
}

impl Default for DataLink {
    fn default() -> Self {
        DataLink::Ethernet
    }
}

enum Protocol {
    ///
    IPv4,

    ///
    Unknown(u16),
}

impl From<u16> for Protocol {
    fn from(value: u16) -> Self {
        use self::Protocol::*;

        match value {
            0x0800 => IPv4,
            v => Unknown(v),
        }
    }
}

impl Into<(u16, u8)> for Protocol {
    fn into(self) -> (u16, u8) {
        use self::Protocol::*;

        match self {
            IPv4 => (0x0800, 4),
            Unknown(v) => (v, 0),
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::IPv4
    }
}
