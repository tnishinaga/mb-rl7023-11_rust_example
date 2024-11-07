use core::net::Ipv6Addr;
use core::str;

use crate::write::ByteWrite;

pub struct Bp35a1Command {}

impl Bp35a1Command {
    pub fn info(writer: &mut impl core::fmt::Write) -> Result<(), core::fmt::Error> {
        write!(writer, "SKINFO\r\n")
    }
    pub fn set_password(
        writer: &mut impl core::fmt::Write,
        password: &str,
    ) -> Result<(), core::fmt::Error> {
        write!(writer, "SKSETPWD {:X} {}\r\n", password.len(), password)
    }

    pub fn set_rbid(writer: &mut impl core::fmt::Write, id: &str) -> Result<(), core::fmt::Error> {
        write!(writer, "SKSETRBID {}\r\n", id)
    }

    pub fn set_sreg(
        writer: &mut impl core::fmt::Write,
        sreg: &Sreg,
    ) -> Result<(), core::fmt::Error> {
        write!(writer, "SKSREG {}\r\n", sreg)
    }

    // SKJOIN
    pub fn join(
        writer: &mut impl core::fmt::Write,
        address: &Ipv6Addr,
    ) -> Result<(), core::fmt::Error> {
        let a = address.segments();
        write!(
            writer,
            "SKJOIN {:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}\r\n",
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]
        )
    }

    fn print_ipv6_address(
        writer: &mut impl core::fmt::Write,
        address: &Ipv6Addr,
    ) -> Result<(), core::fmt::Error> {
        let a = address.segments();
        write!(
            writer,
            "{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}",
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]
        )
    }

    // send_to
    pub fn udp_send(
        writer: &mut impl ByteWrite,
        handle: u8,
        destination_address: &Ipv6Addr,
        destination_port: u16,
        security: bool,
        data: &[u8],
    ) -> Result<(), core::fmt::Error> {
        // SKSENDTO 1 FE80:0000:0000:0000:0280:8700:2004:CDA3 0E1A 1 0 000E \x10\x81\x00\x01\x05\xFF\x01\x02\x88\x01\x62\x01\xE7\x00\r\n
        write!(writer, "SKSENDTO ")?;
        write!(writer, "{} ", handle)?;
        Self::print_ipv6_address(writer, destination_address)?;
        write!(writer, " {:04X} ", destination_port)?;
        write!(writer, "{} ", if security { 1 } else { 0 })?;
        write!(writer, "0 ")?;
        write!(writer, "{:04X} ", data.len())?;
        writer.byte_write(data)?;
        write!(writer, "\r\n")
    }

    pub fn scan(
        writer: &mut impl core::fmt::Write,
        duration_sec: u8,
    ) -> Result<(), core::fmt::Error> {
        write!(writer, "SKSCAN 2 FFFFFFFF {} 0\r\n", duration_sec)
    }

    pub fn skll64(
        writer: &mut impl core::fmt::Write,
        mac_address: u64,
    ) -> Result<(), core::fmt::Error> {
        write!(writer, "SKLL64 {:016X}\r\n", mac_address)
    }
}

pub enum Sreg {
    S2(u8),
    S3(u16),
}

impl core::fmt::Display for Sreg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Sreg::S2(x) => write!(f, "S2 {:02X}", x),
            Sreg::S3(x) => write!(f, "S3 {:04X}", x),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write;

    use super::*;

    // const MAX_CAPACITY: usize = 512;
}
