/// ARP operations
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Operation {
    ///
    Request,

    ///
    Reply,

    ///
    Unknown(u8),
}

impl From<u8> for Operation {
    fn from(value: u8) -> Operation {
        use self::Operation::*;

        match value {
            1 => Request,
            2 => Reply,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for Operation {
    fn into(self) -> u8 {
        use self::Operation::*;

        match self {
            Request => 1,
            Reply => 2,
            Unknown(v) => v,
        }
    }
}
