// This code is based on https://github.com/embassy-rs/embassy/blob/main/examples/rp/src/bin/ethernet_w5500_tcp_server.rs
// Assisted-by: Codex:GPT-5.6 Luna

#![no_std]
#![no_main]

use bbqueue::{BBBuffer, Consumer, Producer};
use bp35a1::command::Sreg;
use bp35a1::parser::{Bp35a1Parser, EventNumber};
use bp35a1::{command::Bp35a1Command, parser::Bp35a1Packet};
use core::net::Ipv6Addr;
use core::str::{self};
use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_futures::yield_now;
use embassy_net::{Ipv4Address, Ipv4Cidr, Stack, StackResources, StaticConfigV4};
use embassy_net_wiznet::chip::W5500;
use embassy_net_wiznet::{Device, Runner, State};
use embassy_rp::bind_interrupts;
use embassy_rp::clocks::RoscRng;
use embassy_rp::dma;
use embassy_rp::gpio::Level;
use embassy_rp::gpio::Output;
use embassy_rp::gpio::{Input, Pull};
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, DMA_CH2, DMA_CH3, SPI0, UART0};
use embassy_rp::spi::{Async, Config as SpiConfig, Spi};
use embassy_rp::uart::{
    Config, Error as UartError, InterruptHandler as UartInterruptHandler, Uart, UartRx, UartTx,
};
use embassy_time::{Delay, Duration, Timer};
use embedded_hal_1::delay::DelayNs;
use embedded_hal_bus::spi::ExclusiveDevice;
use embedded_io_async::Write;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    DMA_IRQ_0 => dma::InterruptHandler<DMA_CH0>, dma::InterruptHandler<DMA_CH1>, dma::InterruptHandler<DMA_CH2>, dma::InterruptHandler<DMA_CH3>;
    UART0_IRQ => UartInterruptHandler<UART0>;
});

// include credential info
include!("broute_credential.rs");

const UART_BUF: usize = 1024 * 2;
// Stop a DMA read after a short idle period so variable-length BP35A1 lines
// are delivered without waiting for a fixed-size transfer to fill.
const UART_DMA_IDLE_US: u64 = 1_000;
const UART_QUEUE_SIZE: usize = UART_BUF * 2;
static UART_RX_QUEUE: StaticCell<BBBuffer<UART_QUEUE_SIZE>> = StaticCell::new();
static UART_TX_QUEUE: StaticCell<BBBuffer<UART_QUEUE_SIZE>> = StaticCell::new();

const TCP_BUF_SIZE: usize = 1024;
const TCP_QUEUE_SIZE: usize = TCP_BUF_SIZE;
static TCP_TO_WISUN: StaticCell<BBBuffer<TCP_QUEUE_SIZE>> = StaticCell::new();
static WISUN_TO_TCP: StaticCell<BBBuffer<TCP_QUEUE_SIZE>> = StaticCell::new();

const TCP_PORT: u16 = 3610;

#[embassy_executor::task]
async fn ethernet_task(
    runner: Runner<
        'static,
        W5500,
        ExclusiveDevice<Spi<'static, SPI0, Async>, Output<'static>, Delay>,
        Input<'static>,
        Output<'static>,
    >,
) -> ! {
    info!("W5500: ethernet task started");
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(runner: embassy_net::Runner<'static, Device<'static>>) -> ! {
    info!("network: task started");
    let mut runner = runner;
    runner.run().await
}

#[embassy_executor::task]
async fn tcp_task(
    stack: &'static Stack<'static>,
    mut from_pc: Producer<'static, TCP_QUEUE_SIZE>,
    mut to_pc: Consumer<'static, TCP_QUEUE_SIZE>,
) -> ! {
    info!("TCP: task started");
    static RX_STORAGE: StaticCell<[u8; TCP_BUF_SIZE]> = StaticCell::new();
    static TX_STORAGE: StaticCell<[u8; TCP_BUF_SIZE]> = StaticCell::new();
    static TCP_BUF: StaticCell<[u8; TCP_BUF_SIZE]> = StaticCell::new();
    let rx_storage = RX_STORAGE.init([0u8; TCP_BUF_SIZE]);
    let tx_storage = TX_STORAGE.init([0u8; TCP_BUF_SIZE]);
    let buf = TCP_BUF.init([0u8; TCP_BUF_SIZE]);
    loop {
        let mut socket =
            embassy_net::tcp::TcpSocket::new(*stack, &mut rx_storage[..], &mut tx_storage[..]);
        info!("TCP: listening on port {}", TCP_PORT);
        if socket.accept(TCP_PORT).await.is_err() {
            warn!("TCP: accept failed");
            continue;
        }
        info!("TCP: client connected");
        loop {
            while let Ok(grant) = to_pc.read() {
                if grant.is_empty() {
                    grant.release(0);
                    break;
                }
                debug!("TCP: sending {} bytes to PC", grant.buf().len());
                if socket.write_all(grant.buf()).await.is_err() {
                    warn!("TCP: write to PC failed");
                    grant.release(0);
                    socket.abort();
                    break;
                }
                let size = grant.buf().len();
                grant.release(size);
            }

            match select(
                socket.read(&mut buf[..]),
                Timer::after(Duration::from_millis(1)),
            )
            .await
            {
                Either::First(Ok(0)) => break,
                Either::First(Ok(size)) => {
                    debug!("TCP: received {} bytes from PC", size);
                    loop {
                        match from_pc.grant_exact(size) {
                            Ok(mut grant) => {
                                grant.buf().copy_from_slice(&buf[..size]);
                                grant.commit(size);
                                break;
                            }
                            Err(
                                bbqueue::Error::InsufficientSize | bbqueue::Error::GrantInProgress,
                            ) => {
                                yield_now().await;
                            }
                            Err(_) => {
                                warn!("TCP: input queue unavailable");
                                break;
                            }
                        }
                    }
                }
                Either::First(Err(_)) => {
                    warn!("TCP: read from PC failed");
                    break;
                }
                Either::Second(_) => (),
            }
        }
        socket.abort();
        info!("TCP: client disconnected");
    }
}

async fn receive_tcp_input(
    queue: &mut Consumer<'static, TCP_QUEUE_SIZE>,
    buffer: &mut [u8],
) -> usize {
    loop {
        match queue.read() {
            Ok(grant) => {
                let grant_size = grant.buf().len();
                let size = core::cmp::min(grant_size, buffer.len());
                buffer[..size].copy_from_slice(&grant.buf()[..size]);
                grant.release(grant_size);
                return size;
            }
            Err(bbqueue::Error::InsufficientSize | bbqueue::Error::GrantInProgress) => {
                yield_now().await;
            }
            Err(bbqueue::Error::AlreadySplit) => return 0,
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    info!("boot: firmware started; RP2040 peripherals initialized");

    let mut spi_config = SpiConfig::default();
    spi_config.frequency = 50_000_000;
    info!("W5500: configuring SPI0 at 50 MHz");
    let spi = Spi::new(
        p.SPI0, p.PIN_18, p.PIN_19, p.PIN_16, p.DMA_CH0, p.DMA_CH1, Irqs, spi_config,
    );
    info!("W5500: configuring CS/INT/RESET pins");
    let cs = Output::new(p.PIN_17, Level::High);
    let w5500_int = Input::new(p.PIN_21, Pull::Up);
    let w5500_reset = Output::new(p.PIN_20, Level::High);
    // One TCP listener and one UDP/maintenance socket are enough for this
    // bridge. Keeping eight TX/RX socket buffers wastes a large part of SRAM.
    static ETH_STATE: StaticCell<State<2, 2>> = StaticCell::new();
    info!("W5500: starting chip initialization");
    let (device, runner) = embassy_net_wiznet::new(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        ETH_STATE.init(State::new()),
        ExclusiveDevice::new(spi, cs, Delay),
        w5500_int,
        w5500_reset,
    )
    .await
    .unwrap();
    info!("W5500: initialized");
    info!("W5500: spawning ethernet runner");
    spawner.spawn(unwrap!(ethernet_task(runner)));

    static STACK: StaticCell<Stack<'static>> = StaticCell::new();
    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    info!("network: creating IPv4 stack");
    let mut rng = RoscRng;
    let (stack, net_runner) = embassy_net::new(
        device,
        embassy_net::Config::ipv4_static(StaticConfigV4 {
            address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 200, 200), 24),
            gateway: None,
            dns_servers: Default::default(),
        }),
        RESOURCES.init(StackResources::new()),
        rng.next_u64(),
    );
    let stack = STACK.init(stack);
    info!("network: IPv4 stack created");
    spawner.spawn(unwrap!(net_task(net_runner)));
    info!("network: configured as 192.168.200.200/24");

    // reset
    info!("Wi-SUN: resetting module");
    let mut reset_pin = Output::new(p.PIN_15, Level::High);
    info!("Wi-SUN: asserting reset");
    reset_pin.set_low();
    embassy_time::Delay.delay_ms(1000);
    info!("Wi-SUN: releasing reset");
    reset_pin.set_high();
    embassy_time::Delay.delay_ms(1000);
    info!("Wi-SUN: reset complete");

    let (tx_pin, rx_pin, uart) = (p.PIN_0, p.PIN_1, p.UART0);
    info!("UART: configuring UART0");

    let uart_config = Config::default();
    info!(
        "UART: DMA baudrate={} data_bits=8 stop_bits=1 parity=none; idle_timeout_us={} queue={}",
        uart_config.baudrate, UART_DMA_IDLE_US, UART_QUEUE_SIZE
    );
    let uart = Uart::new(
        uart,
        tx_pin,
        rx_pin,
        Irqs,
        p.DMA_CH2,
        p.DMA_CH3,
        uart_config,
    );
    info!("UART: initialized");
    let (uart_tx, uart_rx) = uart.split();
    info!("UART: split into TX/RX");
    let (tx_producer, tx_consumer) = UART_TX_QUEUE.init(BBBuffer::new()).try_split().unwrap();
    let (rx_producer, rx_consumer) = UART_RX_QUEUE.init(BBBuffer::new()).try_split().unwrap();
    let (tcp_to_wisun_producer, mut tcp_to_wisun_consumer) =
        TCP_TO_WISUN.init(BBBuffer::new()).try_split().unwrap();
    let (mut wisun_to_tcp_producer, wisun_to_tcp_consumer) =
        WISUN_TO_TCP.init(BBBuffer::new()).try_split().unwrap();
    info!("queues: initialized");

    spawner.spawn(unwrap!(uart_reader(uart_rx, rx_producer)));
    spawner.spawn(unwrap!(uart_writer(uart_tx, tx_consumer)));
    spawner.spawn(unwrap!(tcp_task(
        stack,
        tcp_to_wisun_producer,
        wisun_to_tcp_consumer,
    )));
    info!("tasks: UART and TCP tasks started");

    // pana_auth(&mut writer, &mut rx);

    let mut manager = Bp35a1Manager::new(tx_producer, rx_consumer);

    info!("Wi-SUN: starting PANA authentication");
    let remote_ipv6 = loop {
        match manager.pana_auth().await {
            Ok(ipv6) => break ipv6,
            Err(_) => (),
        }

        defmt::info!("pana_auth NG");

        core::todo!("retry");
    };

    defmt::info!("pana_auth OK");
    info!("Wi-SUN: PANA authentication completed");

    // TCPとWi-SUNのどちらか先に到着したパケットを転送する。
    static TCP_PACKET: StaticCell<[u8; TCP_BUF_SIZE]> = StaticCell::new();
    static WISUN_PACKET: StaticCell<[u8; TCP_BUF_SIZE]> = StaticCell::new();
    let tcp_packet = TCP_PACKET.init([0u8; TCP_BUF_SIZE]);
    let wisun_packet = WISUN_PACKET.init([0u8; TCP_BUF_SIZE]);
    info!("bridge: TCP <-> Wi-SUN forwarding started");
    loop {
        match select(
            receive_tcp_input(&mut tcp_to_wisun_consumer, &mut tcp_packet[..]),
            manager.receive_udp_packet(&mut wisun_packet[..]),
        )
        .await
        {
            // PCから受信したデータは、そのままスマートメーターへ送る。
            Either::First(size) => {
                if size == 0 {
                    continue;
                }
                debug!("bridge: TCP -> Wi-SUN ({} bytes)", size);
                if manager
                    .send_udp_packet(&tcp_packet[..size], &remote_ipv6, TCP_PORT)
                    .await
                    .is_err()
                {
                    warn!("Wi-SUN: failed to send UDP packet");
                }
            }

            // スマートメーターから受信したデータは、TCP接続がある場合だけ
            // tcp_taskへ渡す。tcp_task側で接続がなければ送信されず破棄される。
            Either::Second(Ok(size)) => {
                if size == 0 {
                    continue;
                }
                debug!("bridge: Wi-SUN -> TCP ({} bytes)", size);
                loop {
                    match wisun_to_tcp_producer.grant_exact(size) {
                        Ok(mut grant) => {
                            grant.buf().copy_from_slice(&wisun_packet[..size]);
                            grant.commit(size);
                            break;
                        }
                        Err(bbqueue::Error::InsufficientSize | bbqueue::Error::GrantInProgress) => {
                            yield_now().await;
                        }
                        Err(bbqueue::Error::AlreadySplit) => {
                            warn!("TCP queue is already split");
                            break;
                        }
                    }
                }
            }
            Either::Second(Err(_)) => {
                warn!("Wi-SUN: failed to receive UDP packet");
            }
        }
    }
}

#[embassy_executor::task]
async fn uart_reader(
    mut uart_rx: UartRx<'static, embassy_rp::uart::Async>,
    mut queue: Producer<'static, UART_QUEUE_SIZE>,
) {
    info!(
        "UART RX: DMA reader task started (idle_timeout_us={})",
        UART_DMA_IDLE_US
    );
    let mut error_count = 0u32;
    let mut queue_waits = 0u32;
    loop {
        let mut grant = match queue.grant_max_remaining(UART_BUF) {
            Ok(grant) => grant,
            Err(bbqueue::Error::InsufficientSize | bbqueue::Error::GrantInProgress) => {
                queue_waits += 1;
                if queue_waits == 1 || queue_waits % 128 == 0 {
                    warn!(
                        "UART RX DMA: software queue full (waits={}, capacity={}); consumer is behind",
                        queue_waits, UART_QUEUE_SIZE
                    );
                }
                yield_now().await;
                continue;
            }
            Err(bbqueue::Error::AlreadySplit) => {
                warn!("UART RX: queue is no longer available");
                yield_now().await;
                continue;
            }
        };
        let capacity = grant.buf().len();
        // BP35A1 packets are ASCII. The sentinel lets us determine how many
        // bytes DMA wrote when the idle timeout aborts a partially-filled DMA
        // transfer.
        grant.buf().fill(0xff);
        match select(
            uart_rx.read(grant.buf()),
            Timer::after(Duration::from_micros(UART_DMA_IDLE_US)),
        )
        .await
        {
            Either::First(Ok(())) => {
                debug!("UART RX DMA: received {} bytes", capacity);
                grant.commit(capacity);
            }
            Either::Second(_) => {
                let size = grant
                    .buf()
                    .iter()
                    .position(|byte| *byte == 0xff)
                    .unwrap_or(capacity);
                if size == 0 {
                    grant.commit(0);
                    continue;
                }
                debug!("UART RX DMA: received {} bytes before idle", size);
                grant.commit(size);
            }
            Either::First(Err(UartError::Overrun)) => {
                error_count += 1;
                warn!(
                    "UART RX DMA: OVERRUN #{}; hardware FIFO/shift register overflowed",
                    error_count
                );
                grant.commit(0);
                yield_now().await;
            }
            Either::First(Err(UartError::Break)) => {
                error_count += 1;
                warn!(
                    "UART RX DMA: BREAK error #{}; dropping this read",
                    error_count
                );
                grant.commit(0);
                yield_now().await;
            }
            Either::First(Err(UartError::Parity)) => {
                error_count += 1;
                warn!(
                    "UART RX DMA: PARITY error #{}; dropping this read",
                    error_count
                );
                grant.commit(0);
                yield_now().await;
            }
            Either::First(Err(UartError::Framing)) => {
                error_count += 1;
                warn!(
                    "UART RX DMA: FRAMING error #{}; dropping this read",
                    error_count
                );
                grant.commit(0);
                yield_now().await;
            }
            Either::First(Err(_)) => {
                error_count += 1;
                warn!(
                    "UART RX DMA: unknown serial error #{}; dropping this read",
                    error_count
                );
                grant.commit(0);
                yield_now().await;
            }
        }
    }
}

#[embassy_executor::task]
async fn uart_writer(
    mut uart_tx: UartTx<'static, embassy_rp::uart::Async>,
    mut queue: Consumer<'static, UART_QUEUE_SIZE>,
) {
    info!("UART TX: DMA writer task started");
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
        let size = grant.buf().len();
        match uart_tx.write(grant.buf()).await {
            Ok(()) => {
                debug!("UART TX DMA: transmitted {} bytes", size);
                grant.release(size);
            }
            Err(UartError::Overrun) => {
                warn!("UART TX DMA: overrun error; dropping {} bytes", size);
                grant.release(0);
            }
            Err(UartError::Break) => {
                warn!("UART TX DMA: break error; dropping {} bytes", size);
                grant.release(0);
            }
            Err(UartError::Parity) => {
                warn!("UART TX DMA: parity error; dropping {} bytes", size);
                grant.release(0);
            }
            Err(UartError::Framing) => {
                warn!("UART TX DMA: framing error; dropping {} bytes", size);
                grant.release(0);
            }
            Err(_) => {
                warn!("UART TX DMA: unknown error; dropping {} bytes", size);
                grant.release(0);
            }
        }
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
        defmt::debug!(
            "Wi-SUN TX: sending {} bytes to UDP port {}",
            data.len(),
            destination_port
        );
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

        defmt::debug!("Wi-SUN TX: send completed");
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
                    defmt::debug!("Wi-SUN RX: received {} bytes", size);
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
        defmt::info!("PANA: authentication sequence started");
        // set id/password
        defmt::debug!("PANA: setting credentials");
        Bp35a1Command::set_password(self, BROUTE_PASSWORD).unwrap();
        Bp35a1Command::set_rbid(self, BROUTE_ID).unwrap();
        // check response
        self.check_response().await.unwrap();
        self.check_response().await.unwrap();

        // TODO:scan
        defmt::info!("PANA: scanning for smart meter");
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
                    defmt::info!("PANA: PAN description received");
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
        defmt::debug!("PANA: requesting IPv6 address");
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
            defmt::info!("PANA: IPv6 address received");
            break ipv6;
        };

        // set channel
        defmt::debug!("PANA: configuring channel and PAN ID");
        Bp35a1Command::set_sreg(self, &Sreg::S2(pan_desc.channel)).unwrap();
        // set PanID
        Bp35a1Command::set_sreg(self, &Sreg::S3(pan_desc.pan_id)).unwrap();
        // check response
        self.check_response().await.unwrap();
        self.check_response().await.unwrap();

        // skjoin
        defmt::info!("PANA: joining smart meter");
        Bp35a1Command::join(self, &ipv6).unwrap();
        self.check_response().await.unwrap();
        // check event
        loop {
            match self.receive_bp35a1_packet().await.unwrap() {
                Bp35a1Packet::Event(event) => match &event.number {
                    EventNumber::PanaConnectionFail => {
                        // pana auth error
                        defmt::warn!("PANA: connection failed");
                        return Err(());
                    }
                    EventNumber::PanaConnectionSuccess => {
                        // pana auth ok
                        defmt::info!("PANA: connection succeeded");
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
    type Error = embedded_io_async_06::ErrorKind;

    async fn send(
        &mut self,
        _local: core::net::SocketAddr,
        _remote: core::net::SocketAddr,
        _data: &[u8],
    ) -> Result<(), Self::Error> {
        // TODO: SEND_TO
        core::todo!()
    }

    async fn receive_into(
        &mut self,
        _buffer: &mut [u8],
    ) -> Result<(usize, core::net::SocketAddr, core::net::SocketAddr), Self::Error> {
        // put received data from channel
        core::todo!()
    }
}
