use std::fmt;
use std::net::{AddrParseError, IpAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ClientIp(IpAddr);

impl ClientIp {
    // An IPv4 client reached over IPv6 shows up as a mapped address; canonicalising keeps it one
    // client wherever it is compared, counted or stored.
    pub fn new(ip: IpAddr) -> Self {
        Self(ip.to_canonical())
    }

    pub fn addr(self) -> IpAddr {
        self.0
    }
}

impl From<IpAddr> for ClientIp {
    fn from(ip: IpAddr) -> Self {
        Self::new(ip)
    }
}

impl FromStr for ClientIp {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self::new)
    }
}

impl TryFrom<String> for ClientIp {
    type Error = AddrParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<ClientIp> for String {
    fn from(value: ClientIp) -> Self {
        value.to_string()
    }
}

impl fmt::Display for ClientIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mapped_ipv4_address_is_the_same_client_as_the_plain_one() {
        let mapped: ClientIp = "::ffff:192.0.2.1".parse().expect("ip");
        let plain: ClientIp = "192.0.2.1".parse().expect("ip");
        assert_eq!(mapped, plain);
        assert_eq!(mapped.to_string(), "192.0.2.1");
    }

    #[test]
    fn serializes_as_its_canonical_text() {
        let ip: ClientIp = "2001:0db8:0000::0001".parse().expect("ip");
        let json = serde_json::to_string(&ip).expect("serialize");
        assert_eq!(json, "\"2001:db8::1\"");
        assert_eq!(serde_json::from_str::<ClientIp>(&json).expect("parse"), ip);
        assert!(serde_json::from_str::<ClientIp>("\"not an ip\"").is_err());
    }
}
