//! This example implements a TCP echo server on port 1234 and using DHCP.
//! Send it some data, you should see it echoed back and printed in the console.
//!
//! Example written for the [`WIZnet W5500-EVB-Pico`](https://www.wiznet.io/product-item/w5500-evb-pico/) board.

#![no_std]
#![no_main]

use core::fmt::Debug;
use core::net::Ipv6Addr;
use core::ops::Sub;
use core::slice::SliceIndex;
use core::str::{self, FromStr};

use bbqueue::{BBBuffer, Consumer, GrantR, Producer};
use bp35a1::command::Sreg;
use bp35a1::parser::{Bp35a1Parser, Event, EventNumber, Info};
use bp35a1::{command::Bp35a1Command, parser::Bp35a1Packet};
use cortex_m::prelude::_embedded_hal_blocking_serial_Write;
use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::yield_now;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::Level;
use embassy_rp::gpio::Output;
use embassy_rp::peripherals::UART0;
use embassy_rp::uart::BufferedUartTx;
use embassy_rp::uart::{BufferedInterruptHandler, BufferedUart, BufferedUartRx, Config};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::blocking_mutex::NoopMutex;
use embassy_sync::channel;
use embassy_sync::channel::{Channel, Sender};
use embassy_sync::pipe::Pipe;
use embassy_time::Timer;
use embedded_hal_1::delay::DelayNs;
use embedded_io_async::{Read, Write};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    UART0_IRQ => BufferedInterruptHandler<UART0>;
});

// include credential info
include!("broute_credential.rs");

const TRANSACTION_INDEX_OFFSET: usize = 2;
const ECHONET_LITE_FLAME: &[u8; 14] = &[
    0x10, 0x81, //echonet lite header
    0x00, 0x00, // transaction ID
    0x05, 0xFF, 0x01, // SEOJ(source is controller)
    0x02, 0x88, 0x01, // DEOJ(destination is smart meter)
    0x62, // ESV(Get)
    0x01, // OPC
    0xE7, // EPC(瞬時電力計測値)
    0x00, // PDC
          // EDT
];

const ECHONET_LITE_HEADER_MAGIC: [u8; 2] = [0x10, 0x81];
const RESP_GET_RESP_INDEX_OFFSET_AND_DATA: (usize, u8) = (10, 0x72); // Get Response
const RESP_POWER_CONSUMPTION_OFFSET: usize = 17; // Get Response
const RESP_PDC_OFFSET: usize = 16;

const UART_BUF: usize = 1024 * 8;

const UART_QUEUE_SIZE: usize = UART_BUF * 2;
static UART_RX_QUEUE: BBBuffer<UART_QUEUE_SIZE> = bbqueue::BBBuffer::new();
static UART_TX_QUEUE: BBBuffer<UART_QUEUE_SIZE> = bbqueue::BBBuffer::new();

static LATEST_CURRENT_POWER_CONSUMPTION: embassy_sync::mutex::Mutex<ThreadModeRawMutex, u32> =
    embassy_sync::mutex::Mutex::new(0);

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // reset
    let mut reset_pin = Output::new(p.PIN_15, Level::High);
    reset_pin.set_low();
    embassy_time::Delay.delay_ms(1000);
    reset_pin.set_high();
    embassy_time::Delay.delay_ms(1000);

    let (tx_pin, rx_pin, uart) = (p.PIN_0, p.PIN_1, p.UART0);

    static TX_BUF: StaticCell<[u8; UART_BUF]> = StaticCell::new();
    let tx_buf = &mut TX_BUF.init([0; UART_BUF])[..];
    static RX_BUF: StaticCell<[u8; UART_BUF]> = StaticCell::new();
    let rx_buf = &mut RX_BUF.init([0; UART_BUF])[..];
    let uart = BufferedUart::new(
        uart,
        Irqs,
        tx_pin,
        rx_pin,
        tx_buf,
        rx_buf,
        Config::default(),
    );
    let (uart_tx, uart_rx) = uart.split();
    let (tx_producer, tx_consumer) = UART_TX_QUEUE.try_split().unwrap();
    let (rx_producer, rx_consumer) = UART_RX_QUEUE.try_split().unwrap();

    unwrap!(spawner.spawn(uart_reader(uart_rx, rx_producer)));
    unwrap!(spawner.spawn(uart_writer(uart_tx, tx_consumer)));

    // pana_auth(&mut writer, &mut rx);

    let mut manager = Bp35a1Manager::new(tx_producer, rx_consumer);

    let remote_ipv6 = loop {
        match manager.pana_auth().await {
            Ok(ipv6) => break ipv6,
            Err(_) => (),
        }

        defmt::info!("pana_auth NG");

        core::todo!("retry");
    };

    defmt::info!("pana_auth OK");

    let mut transaction_count = 0u16;
    loop {
        // send echonet packet and receive power data
        let mut packet = ECHONET_LITE_FLAME.clone();
        packet[TRANSACTION_INDEX_OFFSET..TRANSACTION_INDEX_OFFSET + 2]
            .clone_from_slice(&transaction_count.to_be_bytes());

        manager
            .send_udp_packet(&packet, &remote_ipv6, 0x0E1A)
            .await
            .unwrap();

        loop {
            let mut buf = [0u8; 1024];
            let size = manager.receive_udp_packet(&mut buf).await.unwrap();
            defmt::debug!("{=[u8]:x}", &buf[..size]);

            // parse echonet packet
            let maybe_echonet_packet = &buf[..size];
            if &maybe_echonet_packet[0..2] != ECHONET_LITE_HEADER_MAGIC {
                // it is not echonet packet
                defmt::debug!("packet is not echonet-lite");
                embassy_futures::yield_now().await;
                continue;
            }
            // check transaction ID
            let tid = u16::from_be_bytes(
                maybe_echonet_packet[TRANSACTION_INDEX_OFFSET..TRANSACTION_INDEX_OFFSET + 2]
                    .try_into()
                    .unwrap(),
            );
            if tid != transaction_count {
                defmt::debug!("transaction id missmuch");
                defmt::debug!("tdi {} != transaction_count {}", tid, transaction_count);
                embassy_futures::yield_now().await;
                continue;
            }

            // check ESV
            let (index, esv) = RESP_GET_RESP_INDEX_OFFSET_AND_DATA;
            if maybe_echonet_packet[index] != esv {
                defmt::debug!("esv missmuch");
                embassy_futures::yield_now().await;
                continue;
            }

            // assume SEOJ, DEOJ, OPC, EPC, POC are valid
            // TODO: check

            let pdc_size = maybe_echonet_packet[RESP_PDC_OFFSET];
            let pdc: u32 = match pdc_size {
                1 => maybe_echonet_packet[RESP_POWER_CONSUMPTION_OFFSET].into(),
                2 => u16::from_be_bytes(
                    maybe_echonet_packet[RESP_POWER_CONSUMPTION_OFFSET..]
                        .try_into()
                        .unwrap(),
                )
                .into(),
                _ => core::panic!("pdc too large"),
            };
            defmt::info!("total power consumption: {}W", pdc);
            let mut latest_pc = LATEST_CURRENT_POWER_CONSUMPTION.lock().await;
            *latest_pc = pdc;
            break;
        }

        embassy_futures::yield_now().await;
        transaction_count += 1;
        embassy_time::Delay.delay_ms(1000 * 10);
    }
}

#[embassy_executor::task]
async fn uart_reader(
    mut uart_rx: BufferedUartRx<'static, UART0>,
    mut queue: Producer<'static, UART_QUEUE_SIZE>,
) {
    loop {
        let mut grant = queue.grant_max_remaining(UART_BUF).unwrap();
        if grant.is_empty() {
            embassy_futures::yield_now().await;
            continue;
        }
        let size = uart_rx.read(&mut grant.buf()).await.unwrap();
        // debug!("uart RX {=[u8]:a}", grant.buf()[..size]);
        grant.commit(size);
    }
}

#[embassy_executor::task]
async fn uart_writer(
    mut uart_tx: BufferedUartTx<'static, UART0>,
    mut queue: Consumer<'static, UART_QUEUE_SIZE>,
) {
    loop {
        let grant = match queue.read() {
            Ok(ok) => Ok(ok),
            Err(e) => match e {
                bbqueue::Error::InsufficientSize | bbqueue::Error::GrantInProgress => {
                    embassy_futures::yield_now().await;
                    continue;
                }
                bbqueue::Error::AlreadySplit => Err(bbqueue::Error::AlreadySplit),
            },
        }
        .unwrap();
        if grant.is_empty() {
            embassy_futures::yield_now().await;
            continue;
        }
        debug!("TX {=[u8]:a}", grant.buf());
        let size = uart_tx.write(grant.buf()).await.unwrap();
        grant.release(size);
    }
}

struct Bp35a1Manager {
    uart_tx: Producer<'static, UART_QUEUE_SIZE>,
    uart_rx: Consumer<'static, UART_QUEUE_SIZE>,
}

impl Bp35a1Manager {
    pub fn new(
        uart_tx: Producer<'static, UART_QUEUE_SIZE>,
        uart_rx: Consumer<'static, UART_QUEUE_SIZE>,
    ) -> Self {
        Self { uart_tx, uart_rx }
    }

    async fn send_udp_packet(
        &mut self,
        data: &[u8],
        destination_address: &Ipv6Addr,
        destination_port: u16,
    ) -> Result<(), ()> {
        defmt::debug!("send_udp_packet");
        Bp35a1Command::udp_send(self, 1, destination_address, destination_port, true, data)
            .unwrap();
        // skip echo
        defmt::debug!("skip echo");
        match self.receive_bp35a1_packet().await? {
            Bp35a1Packet::EchoBack => (),
            _ => return Err(()),
        }
        // check finish
        defmt::debug!("check finish");
        match self.receive_bp35a1_packet().await? {
            Bp35a1Packet::Event(event) => {
                if event.number != EventNumber::UdpSendFinish {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
        // check OK
        defmt::debug!("check ok");
        let _ = match self.receive_bp35a1_packet().await? {
            Bp35a1Packet::Response(resp) => resp.unwrap(),
            _ => return Err(()),
        };

        Ok(())
    }

    // let size = manager.receive_udp_packet(&mut buf).await.unwrap();
    async fn receive_udp_packet(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        defmt::debug!("receive_udp_packet");
        let size = loop {
            match self.receive_bp35a1_packet().await.unwrap() {
                Bp35a1Packet::UdpPacket(udp_packet) => {
                    // convert hex string to u8 array
                    let size = udp_packet.data_size;
                    let grant = self.uart_rx.read().unwrap();
                    let packet_hexstring = &grant.buf()[..size * 2];
                    for (i, p) in packet_hexstring.chunks(2).enumerate() {
                        let byte = u8::from_str_radix(str::from_utf8(p).unwrap(), 16).unwrap();
                        buf[i] = byte;
                    }
                    grant.release(size * 2 + 2);
                    break size;
                }
                _ => {
                    embassy_futures::yield_now().await;
                    continue;
                }
            }
        };
        Ok(size)
    }

    async fn check_response(&mut self) -> Result<(), ()> {
        for x in [Bp35a1Packet::EchoBack, Bp35a1Packet::Response(Ok(()))] {
            let p = self.receive_bp35a1_packet().await?;
            if x != p {
                debug!("response: {:?}", defmt::Debug2Format(&p));
                return Err(());
            }
        }

        Ok(())
    }

    pub async fn get_local_info(&mut self) -> Result<Info, ()> {
        Bp35a1Command::info(self).unwrap();
        loop {
            match self.receive_bp35a1_packet().await.unwrap() {
                Bp35a1Packet::EchoBack => break,
                _ => {
                    embassy_futures::yield_now().await;
                    continue;
                }
            }
        }
        let info = loop {
            match self.receive_bp35a1_packet().await.unwrap() {
                Bp35a1Packet::Info(info) => break info,
                _ => {
                    embassy_futures::yield_now().await;
                    continue;
                }
            }
        };
        Ok(info)
    }

    async fn receive_bp35a1_packet_inner(&mut self) -> Result<Option<Bp35a1Packet>, ()> {
        let grant = match self.uart_rx.read() {
            Ok(ok) => Ok(ok),
            Err(e) => match e {
                bbqueue::Error::InsufficientSize | bbqueue::Error::GrantInProgress => {
                    embassy_futures::yield_now().await;
                    return Ok(None);
                }
                bbqueue::Error::AlreadySplit => Err(bbqueue::Error::AlreadySplit),
            },
        }
        .unwrap();

        let buf = grant.buf();
        // info!("buf {=[u8]:a}", buf);
        let (t, p) = match Bp35a1Parser::parse(buf) {
            Ok((t, p)) => (t, p),
            Err(e) => match e {
                nom::Err::Incomplete(_) => {
                    return Ok(None);
                }
                _ => {
                    error!("parse error: {:?}", defmt::Debug2Format(&e));
                    error!("parse error buf: {=[u8]:a}", buf);
                    return Err(());
                }
            },
        };
        let used_size = buf.len() - t.len();
        debug!("buf {=[u8]:a}", grant.buf()[..used_size]);
        debug!("buf all {=[u8]:a}", grant.buf());
        debug!("used_size: {}", used_size);
        grant.release(used_size);
        // if let Ok(x) = self.uart_rx.read() {
        //     info!("buf released: {=[u8]:a}", x.buf());
        // } else {
        //     ()
        // }
        return Ok(Some(p));
    }

    async fn receive_bp35a1_packet(&mut self) -> Result<Bp35a1Packet, ()> {
        loop {
            match self.receive_bp35a1_packet_inner().await {
                Ok(ok) => {
                    if let Some(x) = ok {
                        defmt::debug!("{:?}", Debug2Format(&x));
                        return Ok(x);
                    } else {
                        embassy_futures::yield_now().await;
                        continue;
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn pana_auth(&mut self) -> Result<Ipv6Addr, ()> {
        defmt::trace!("start pana_auth");
        // set id/password
        Bp35a1Command::set_password(self, BROUTE_PASSWORD).unwrap();
        Bp35a1Command::set_rbid(self, BROUTE_ID).unwrap();
        // check response
        self.check_response().await.unwrap();
        self.check_response().await.unwrap();

        // TODO:scan
        let pan_desc = loop {
            Bp35a1Command::scan(self, 3).unwrap();
            self.check_response().await.unwrap();

            // beaconを受信したらpan descriptionが来る
            match self.receive_bp35a1_packet().await.unwrap() {
                Bp35a1Packet::Event(event) => match &event.number {
                    EventNumber::ActiveScanFinish => {
                        // not found?
                        embassy_futures::yield_now().await;
                        continue;
                    }
                    EventNumber::BeaconReceived => {
                        defmt::info!("BeaconReceived");
                    }
                    _e => {
                        defmt::info!("recv {:?}", defmt::Debug2Format(_e));
                        core::unreachable!()
                    }
                },
                _ => core::unreachable!(),
            }

            match self.receive_bp35a1_packet().await.unwrap() {
                Bp35a1Packet::PanDescription(desc) => {
                    break desc;
                }
                _e => {
                    // wait
                    defmt::info!("epan {:?}", defmt::Debug2Format(&_e));
                    embassy_futures::yield_now().await;
                    continue;
                }
            }
        };

        // wait scan finish
        loop {
            defmt::info!("wait scan finish");

            match self.receive_bp35a1_packet().await.unwrap() {
                Bp35a1Packet::Event(event) => match &event.number {
                    EventNumber::ActiveScanFinish => {
                        break;
                    }
                    _e => {
                        defmt::info!("recv {:?}", defmt::Debug2Format(_e));
                        embassy_futures::yield_now().await;
                        continue;
                    }
                },
                _p => {
                    defmt::info!("recv {:?}", defmt::Debug2Format(&_p));
                    embassy_futures::yield_now().await;
                    continue;
                }
            }
        }

        // get address
        Bp35a1Command::skll64(self, pan_desc.mac_address).unwrap();
        // skip echoback
        let _ = self.receive_bp35a1_packet().await.unwrap();

        // get adress
        // TODO: check_responseと一部コードを共通化する
        let ipv6 = loop {
            let grant = match self.uart_rx.read() {
                Ok(ok) => Ok(ok),
                Err(e) => match e {
                    bbqueue::Error::InsufficientSize | bbqueue::Error::GrantInProgress => {
                        embassy_futures::yield_now().await;
                        continue;
                    }
                    bbqueue::Error::AlreadySplit => Err(bbqueue::Error::AlreadySplit),
                },
            }
            .unwrap();
            let buf = grant.buf();
            info!("buf {=[u8]:a}", buf);

            let (r, ipv6) = match bp35a1::parser::skell64_parser(buf) {
                Ok((t, p)) => (t, p),
                Err(e) => match e {
                    nom::Err::Incomplete(_) => {
                        embassy_futures::yield_now().await;
                        continue;
                    }
                    _ => {
                        debug!("parse error: {:?}", defmt::Debug2Format(&e));
                        return Err(());
                    }
                },
            };
            let used_size = buf.len() - r.len();
            grant.release(used_size);
            break ipv6;
        };

        // set channel
        Bp35a1Command::set_sreg(self, &Sreg::S2(pan_desc.channel)).unwrap();
        // set PanID
        Bp35a1Command::set_sreg(self, &Sreg::S3(pan_desc.pan_id)).unwrap();
        // check response
        self.check_response().await.unwrap();
        self.check_response().await.unwrap();

        // skjoin
        Bp35a1Command::join(self, &ipv6).unwrap();
        self.check_response().await.unwrap();
        // check event
        loop {
            match self.receive_bp35a1_packet().await.unwrap() {
                Bp35a1Packet::Event(event) => match &event.number {
                    EventNumber::PanaConnectionFail => {
                        // pana auth error
                        return Err(());
                    }
                    EventNumber::PanaConnectionSuccess => {
                        // pana auth ok
                        return Ok(ipv6);
                    }
                    EventNumber::UdpSendFinish => {
                        // wait
                        embassy_futures::yield_now().await;
                        continue;
                    }
                    EventNumber::NaReceived => {
                        // wait
                        embassy_futures::yield_now().await;
                        continue;
                    }
                    _e => {
                        debug!("event: {:?}", defmt::Debug2Format(&_e));
                        core::unreachable!()
                    }
                },
                Bp35a1Packet::UdpPacket(udp) => {
                    defmt::debug!("Receive udp packet, skip");
                    // skip data and \r\n
                    let grant = self.uart_rx.read().unwrap();
                    grant.release(udp.data_size * 2 + 2);
                }
                _ => core::unreachable!(),
            }
        }
    }
}

impl core::fmt::Write for Bp35a1Manager {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let mut grant = self
            .uart_tx
            .grant_exact(s.as_bytes().len())
            .map_err(|_e| core::fmt::Error)?;
        grant.buf().copy_from_slice(s.as_bytes());
        grant.commit(s.as_bytes().len());
        Ok(())
    }
}

impl bp35a1::write::ByteWrite for Bp35a1Manager {
    fn byte_write(&mut self, data: &[u8]) -> Result<usize, core::fmt::Error> {
        let mut grant = self
            .uart_tx
            .grant_max_remaining(data.len())
            .map_err(|_e| core::fmt::Error)?;
        let buffer_size = grant.buf().len();
        grant.buf().copy_from_slice(&data[..buffer_size]);
        grant.commit(buffer_size);
        Ok(buffer_size)
    }
}

impl embedded_nal_async::UnconnectedUdp for Bp35a1Manager {
    type Error = embedded_io_async::ErrorKind;

    async fn send(
        &mut self,
        local: core::net::SocketAddr,
        remote: core::net::SocketAddr,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        // TODO: SEND_TO
        core::todo!()
    }

    async fn receive_into(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, core::net::SocketAddr, core::net::SocketAddr), Self::Error> {
        // put received data from channel
        core::todo!()
    }
}
