use core::{
    net::Ipv6Addr,
    str::{self, FromStr},
};
use num_enum::{FromPrimitive, IntoPrimitive};

use nom::{
    branch::alt,
    bytes::streaming::{tag, take_until},
    character::streaming::{
        alphanumeric0, digit0, digit1, hex_digit1, line_ending, space0, space1,
    },
    IResult, ParseTo,
};

fn skip_to_next_line(data: &[u8]) -> IResult<&[u8], ()> {
    let r = data;
    let (r, _) = line_ending(r)?;
    let (r, _) = space0(r)?;
    Ok((r, ()))
}

pub fn ipv6<'a>(dr: &'a [u8]) -> IResult<&'a [u8], Ipv6Addr> {
    let (dr, address) = take_until(" ")(dr)?;
    let address = core::net::Ipv6Addr::from_str(str::from_utf8(address).unwrap()).unwrap();
    Ok((dr, address))
}

pub fn skell64_parser(dr: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    let (dr, address) = take_until("\r\n")(dr)?;
    let address = core::net::Ipv6Addr::from_str(str::from_utf8(address).unwrap()).unwrap();
    let (dr, _) = line_ending(dr)?;
    Ok((dr, address))
}

fn hex_digit1_u8(dr: &[u8]) -> IResult<&[u8], u8> {
    let (dr, digit) = hex_digit1(dr)?;
    let digit = u8::from_str_radix(str::from_utf8(digit).unwrap(), 16).unwrap();
    Ok((dr, digit))
}

fn hex_digit1_u16(dr: &[u8]) -> IResult<&[u8], u16> {
    let (dr, digit) = hex_digit1(dr)?;
    let digit = u16::from_str_radix(str::from_utf8(digit).unwrap(), 16).unwrap();
    Ok((dr, digit))
}

fn hex_digit1_u64(dr: &[u8]) -> IResult<&[u8], u64> {
    let (dr, digit) = hex_digit1(dr)?;
    let digit = u64::from_str_radix(str::from_utf8(digit).unwrap(), 16).unwrap();
    Ok((dr, digit))
}

pub struct Bp35a1Parser {}

impl Bp35a1Parser {
    pub fn parse(data: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
        alt((
            Self::response_parser,
            Self::epan_description_parser,
            Self::event_parser,
            Self::echo_back_parser,
            Self::rx_udp_parser,
            Self::info_parser,
            Self::line_ending,
        ))(data)
    }

    pub fn line_ending(data: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
        let (dr, _) = line_ending(data)?;
        Ok((dr, Bp35a1Packet::NeedSkip))
    }

    pub fn response_parser(data: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
        fn ok_func(dr: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
            let (dr, _) = tag(b"OK\r\n")(dr)?;
            Ok((dr, Bp35a1Packet::Response(Ok(()))))
        }
        fn fail_func(dr: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
            let (dr, _fail) = tag(b"FAIL ER")(dr)?;
            let (dr, error) = digit1(dr)?;
            let (dr, _skip) = take_until("\r\n")(dr)?;
            let (dr, _) = line_ending(dr)?;
            Ok((dr, Bp35a1Packet::Response(Err(error.parse_to().unwrap()))))
        }
        let dr: &[u8] = data;

        alt((ok_func, fail_func))(dr)
    }

    pub fn epan_description_parser(data: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
        let r = data;

        let (r, _event) = tag(b"EPANDESC")(r)?;
        let (r, _) = skip_to_next_line(r)?;

        // channel
        let (r, _) = tag(b"Channel:")(r)?;
        let (r, channel) = hex_digit1_u8(r)?;
        let (r, _) = skip_to_next_line(r)?;
        // defmt::info!("Channel Ok");

        // defmt::info!("Channel Page");
        // channel page
        let (r, _) = tag(b"Channel Page:")(r)?;
        let (r, channel_page) = hex_digit1_u8(r)?;
        let (r, _) = skip_to_next_line(r)?;
        // defmt::info!("Channel Page Ok");
        // Pan ID
        let (r, _) = tag(b"Pan ID:")(r)?;
        let (r, pan_id) = hex_digit1_u16(r)?;
        let (r, _) = skip_to_next_line(r)?;
        // defmt::info!("Pan ID Ok");
        // address
        let (r, _) = tag(b"Addr:")(r)?;
        let (r, mac_address) = hex_digit1_u64(r)?;
        let (r, _) = skip_to_next_line(r)?;
        // defmt::info!("Addr Ok");
        // LQI
        let (r, _) = tag(b"LQI:")(r)?;
        let (r, lqi) = hex_digit1_u8(r)?;
        let (r, _) = skip_to_next_line(r)?;
        // defmt::info!("LQI Ok");

        // Side(skip)
        let (r, _) = tag(b"Side:")(r)?;
        let (r, _side) = hex_digit1_u8(r)?;
        let (r, _) = skip_to_next_line(r)?;
        // defmt::info!("Side Ok");

        // option: pair id
        // TODO: PairIDがない場合は一旦考えない
        let (r, _) = tag(b"PairID:")(r)?;
        let (r, pid) = alphanumeric0(r)?;
        let mut pair_id = [0u8; 8];
        let pair_id = if pid.is_empty() {
            None
        } else {
            pair_id[..pid.len()].copy_from_slice(pid);
            Some(pair_id)
        };
        let (r, _) = space0(r)?;
        let (r, _) = line_ending(r)?;

        let pan = PanDescription {
            channel,
            channel_page,
            pan_id,
            mac_address,
            lqi,
            pair_id,
        };

        Ok((r, Bp35a1Packet::PanDescription(pan)))
    }

    pub fn info_parser(data: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
        let dr = data;

        let (dr, _event) = tag(b"EINFO ")(dr)?;
        // addr
        let (dr, address) = ipv6(dr)?;
        let (dr, _) = space1(dr)?;
        // mac
        let (dr, mac) = hex_digit1_u64(dr)?;
        let (dr, _) = space1(dr)?;
        // channel
        let (dr, channel) = hex_digit1_u8(dr)?;
        let (dr, _) = space1(dr)?;
        // panid
        let (dr, pan_id) = hex_digit1_u16(dr)?;
        let (dr, _) = space1(dr)?;
        // FFFE
        let (dr, _) = tag("0 \r\nOK\r\n")(dr)?;

        Ok((
            dr,
            Bp35a1Packet::Info(Info {
                address,
                mac,
                channel,
                pan_id,
            }),
        ))
    }

    pub fn event_parser(data: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
        let dr = data;

        // example
        // b"EVENT 22 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 0\r\n"
        let (dr, _event) = tag(b"EVENT ")(dr)?;
        let (dr, number) = hex_digit1_u8(dr)?;
        let (dr, _) = space1(dr)?;
        // sender(: separated hex u128 values)
        let (dr, sender_address) = ipv6(dr)?;
        let (dr, _) = space0(dr)?;
        // 0
        let (dr, _zero) = digit1(dr)?;
        let (dr, _) = space0(dr)?;
        // 数字があったら取り込む
        let (dr, param) = digit0(dr)?;
        let param = if !param.is_empty() {
            Some(param.parse_to().unwrap())
        } else {
            None
        };
        let (dr, _) = line_ending(dr)?;

        Ok((
            dr,
            Bp35a1Packet::Event(Event {
                number: EventNumber::from(number),
                sender: sender_address,
                param,
            }),
        ))
    }

    /// skip echoback
    pub fn echo_back_parser(data: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
        let dr: &[u8] = data;
        let (dr, _command) = tag(b"SK")(dr)?;
        let (dr, _skip) = take_until("\r\n")(dr)?;
        let (dr, _) = line_ending(dr)?;
        return Ok((dr, Bp35a1Packet::EchoBack));
    }

    pub fn rx_udp_parser(data: &[u8]) -> IResult<&[u8], Bp35a1Packet> {
        let dr: &[u8] = data;
        let (dr, _command) = tag(b"ERXUDP ")(dr)?;
        // sender
        let (dr, sender_address) = ipv6(dr)?;
        let (dr, _) = space0(dr)?;
        // dest
        let (dr, destination_address) = ipv6(dr)?;
        let (dr, _) = space0(dr)?;
        // sender port
        let (dr, sender_port) = hex_digit1_u16(dr)?;
        let (dr, _) = space1(dr)?;
        // dest port
        let (dr, destination_port) = hex_digit1_u16(dr)?;
        let (dr, _) = space1(dr)?;
        // sender mac
        let (dr, sender_mac) = hex_digit1_u64(dr)?;
        let (dr, _) = space1(dr)?;
        // secured flag?
        let (dr, secure_flag) = nom::character::streaming::u8(dr)?;
        let secure_flag = secure_flag == 1;
        let (dr, _) = space1(dr)?;
        // unknown?
        let (dr, unknown) = nom::character::streaming::u8(dr)?;
        let (dr, _) = space1(dr)?;
        // data len
        let (dr, data_len) = hex_digit1_u16(dr)?;
        let (data_start, _) = space1(dr)?;
        // UDPのパケットがバッファに乗り切るかわからないのでここでは解析しない
        // 利用者側で data_len * 2 + 2(\r\n) を取り出して扱う
        // // data
        // let (dr, data) = take_until("\r\n")(dr)?;
        // let (dr, _) = line_ending(dr)?;

        // check data
        let (dr, _data) = nom::bytes::streaming::take(data_len * 2)(data_start)?;
        let (_dr, _) = line_ending(dr)?;

        // if (dr.len() - 2) / 2 != data_len.into() {
        //     defmt::debug!("dr {=[u8]:a}", dr);
        //     defmt::debug!("dr.len() = {}", dr.len());
        //     defmt::debug!("data_len = {}", data_len);
        //     unreachable!();
        // }

        Ok((
            data_start,
            Bp35a1Packet::UdpPacket(UdpPacket {
                sender_address,
                destination_address,
                sender_port,
                destination_port,
                sender_mac,
                secure_flag,
                unknown,
                data_size: data_len.into(), // data_str: data,
            }),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub enum Bp35a1Packet {
    Response(Result<(), u8>),
    PanDescription(PanDescription),
    Event(Event),
    EchoBack,
    UdpPacket(UdpPacket),
    Info(Info),
    NeedSkip,
}

#[derive(Debug, PartialEq)]
pub struct PanDescription {
    pub channel: u8,
    pub channel_page: u8,
    pub pan_id: u16,
    pub mac_address: u64,
    pub lqi: u8,
    pub pair_id: Option<[u8; 8]>,
}

#[derive(Debug, PartialEq)]
pub struct UdpPacket {
    pub sender_address: Ipv6Addr,
    pub destination_address: Ipv6Addr,
    pub sender_port: u16,
    pub destination_port: u16,
    pub sender_mac: u64,
    pub secure_flag: bool,
    unknown: u8,
    pub data_size: usize,
    // data_str: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub struct Info {
    pub address: Ipv6Addr,
    pub mac: u64,
    pub channel: u8,
    pub pan_id: u16,
}

#[repr(u8)]
#[derive(Debug, IntoPrimitive, FromPrimitive, PartialEq)]
pub enum EventNumber {
    NsReceived = 1,
    NaReceived = 2,
    EchoRequestReceived = 5,
    EdScanFinished = 0x1F,
    BeaconReceived = 0x20,
    UdpSendFinish = 0x21,
    ActiveScanFinish = 0x22,
    PanaConnectionFail = 0x24,
    PanaConnectionSuccess = 0x25,
    PanaDisconnectRequestReceived = 0x26,
    PanaDisconnectSuccess = 0x27,
    PanaDisconnectTimeout = 0x28,
    SesstionTimeout = 0x29,
    TotalSendTimeLimitInvoked = 0x32,
    TotalSendTimeLimitCancel = 0x33,
    #[num_enum(default)]
    Unknown,
}

#[derive(Debug, PartialEq)]
pub struct Event {
    pub number: EventNumber,
    pub sender: Ipv6Addr,
    pub param: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn test_epan_description_parser() {
        let text = b"EPANDESC\r\n\
 Channel:21 \r\n\
 Channel Page:09\r\n\
 Pan ID:8888\r\n\
 Addr:001D129012345678\r\n\
 LQI:E1\r\n\
 PairID:FFFFFFFF\r\n";
        let expect = Bp35a1Packet::PanDescription(PanDescription {
            channel: 0x21,
            channel_page: 0x9,
            pan_id: 0x8888,
            mac_address: 0x001D129012345678,
            lqi: 0xE1,
            pair_id: Some(*b"FFFFFFFF"),
        });
        let (dr, pan_desc) = Bp35a1Parser::epan_description_parser(text).unwrap();
        assert_eq!(pan_desc, expect);
        assert_eq!(dr.len(), 0);
    }

    #[test]
    fn test_event() {
        let texts = [
            b"EVENT 22 FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF 0\r\n".as_slice(),
            b"EVENT 21 FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF 0 00\r\n".as_slice(),
        ];
        let expects = [
            Bp35a1Packet::Event(Event {
                number: EventNumber::ActiveScanFinish,
                sender: Ipv6Addr::from_str("FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF").unwrap(),
                param: None,
            }),
            Bp35a1Packet::Event(Event {
                number: EventNumber::UdpSendFinish,
                sender: Ipv6Addr::from_str("FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF").unwrap(),
                param: Some(0),
            }),
        ];
        for (t, e) in texts.iter().zip(expects) {
            let (dr, result) = Bp35a1Parser::event_parser(*t).unwrap();
            assert_eq!(result, e);
            assert_eq!(dr.len(), 0);
        }
    }

    #[test]
    fn test_echoback() {
        let texts: [&[u8]; 2] = [b"SKSETPWD 12 XXXXYYYYZZZZ\r\n", b"SKSREG S2 39\r\n"];
        let expects = [Bp35a1Packet::EchoBack, Bp35a1Packet::EchoBack];
        for (t, e) in texts.iter().zip(expects) {
            let (dr, result) = Bp35a1Parser::echo_back_parser(*t).unwrap();
            assert_eq!(result, e);
            assert_eq!(dr.len(), 0);
        }
    }

    #[test]
    fn test_response_parser() {
        let texts: [&[u8]; 2] = [b"OK\r\n", b"FAIL ER04\r\n"];
        let expects = [
            Bp35a1Packet::Response(Ok(())),
            Bp35a1Packet::Response(Err(4)),
        ];
        for (t, e) in texts.iter().zip(expects) {
            let (dr, result) = Bp35a1Parser::response_parser(*t).unwrap();
            assert_eq!(result, e);
            assert_eq!(dr.len(), 0);
        }
    }

    #[test]
    fn test_rx_udp_parser() {
        let texts: [&[u8]; 1] = [b"ERXUDP FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF FE80:0000:0000:0000:DEEF:DEEF:DEEF:DEEF 02CC 02CC FFFFFFFFFFFFFFFF 0 0 0028 00000000000000000000000000000000000000000000000000000000000000000000000000000000\r\n"];
        let expects = [Bp35a1Packet::UdpPacket(UdpPacket {
            sender_address: Ipv6Addr::from_str("FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF").unwrap(),
            destination_address: Ipv6Addr::from_str("FE80:0000:0000:0000:DEEF:DEEF:DEEF:DEEF")
                .unwrap(),
            sender_port: 0x02CC,
            destination_port: 0x02CC,
            sender_mac: 0xFFFF_FFFF_FFFF_FFFF,
            secure_flag: false,
            unknown: 0,
            data_size: 0x28usize,
            // data_str: &texts[0][texts[0].len() - 2 - 0x28 * 2..texts[0].len() - 2],
        })];
        for (t, e) in texts.iter().zip(expects) {
            let (dr, result) = Bp35a1Parser::rx_udp_parser(*t).unwrap();
            assert_eq!(result, e);
            let size = match result {
                Bp35a1Packet::UdpPacket(udp_packet) => udp_packet.data_size,
                _ => panic!(),
            };
            assert_eq!(dr.len(), size * 2 + 2);
        }
    }

    #[test]
    fn test_real_event() {
        let text = b"SKSETPWD 12 AAAABBBBCCCC\r\n\
        OK\r\n\
        SKSETRBID 00000000000000000000000000000000\r\n\
        OK\r\n\
        SKSREG S2 39\r\n\
        OK\r\n\
        SKSREG S3 ABCD\r\n\
        OK\r\n\
        SKJOIN FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF\r\n\
        OK\r\n\
        EVENT 21 FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF 0 02\r\n\
        SKSENDTO 1 FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF 0E1A 1 0 000E \x81\xff\x88b\xe7\r\n\
        OK\r\n\
        EVENT 02 FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF 0\r\n\
        ERXUDP FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF FE80:0000:0000:0000:DEEF:DEEF:DEEF:DEEF 02CC 02CC FFFFFFFFFFFFFFFF 0 0 0028 00000000000000000000000000000000000000000000000000000000000000000000000000000000\r\n\
        ";
        let expect = [
            // SKSETPWD
            Bp35a1Packet::EchoBack,
            Bp35a1Packet::Response(Ok(())),
            // SKSETRBID
            Bp35a1Packet::EchoBack,
            Bp35a1Packet::Response(Ok(())),
            // SKSREG S2
            Bp35a1Packet::EchoBack,
            Bp35a1Packet::Response(Ok(())),
            // SKSREG S3
            Bp35a1Packet::EchoBack,
            Bp35a1Packet::Response(Ok(())),
            // SKJOIN
            Bp35a1Packet::EchoBack,
            Bp35a1Packet::Response(Ok(())),
            // EVENT 21
            Bp35a1Packet::Event(Event {
                number: EventNumber::UdpSendFinish,
                sender: Ipv6Addr::from_str("FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF").unwrap(),
                param: Some(2),
            }),
            // SKSENDTO
            Bp35a1Packet::EchoBack,
            Bp35a1Packet::Response(Ok(())),
            // EVENT 02
            Bp35a1Packet::Event(Event {
                number: EventNumber::NaReceived,
                sender: Ipv6Addr::from_str("FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF").unwrap(),
                param: None,
            }),
            // ERXUDP
            Bp35a1Packet::UdpPacket(UdpPacket {
                sender_address: Ipv6Addr::from_str("FE80:0000:0000:0000:BEAF:BEAF:BEAF:BEAF")
                    .unwrap(),
                destination_address: Ipv6Addr::from_str("FE80:0000:0000:0000:DEEF:DEEF:DEEF:DEEF")
                    .unwrap(),
                sender_port: 0x02CC,
                destination_port: 0x02CC,
                sender_mac: 0xFFFF_FFFF_FFFF_FFFF,
                secure_flag: false,
                unknown: 0,
                data_size: 0x28usize, // data_str: &text[text.len() - 2 - 0x28 * 2..text.len() - 2],
            }),
        ];
        let mut dr = text.as_slice();
        let mut results: Vec<Bp35a1Packet> = Vec::new();
        while !dr.is_empty() {
            // dbg!(str::from_utf8(dr).unwrap());
            let (t, x) = Bp35a1Parser::parse(dr).unwrap();

            results.push(x);
            dr = t;
        }
        for (r, e) in results.iter().zip(expect) {
            assert_eq!(e, *r);
        }
    }
}
