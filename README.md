<!-- Assisted-by: Codex:GPT-5.6 Luna -->

# MB-RL7023-11 Rustメディアコンバーター

W5500-EVB-Pico（RP2040 + W5500）と、BP35A1を搭載したMB-RL7023-11を使い、PCのTCP通信をWi-SUN経由でスマートメーターへ中継するファームウェアです。

## 構成

- PC側のIPアドレス: `192.168.200.100/24`
- マイコン側のIPアドレス: `192.168.200.200/24`
- TCP待受ポート: `3610`
- Wi-SUNモジュールとの接続: UART0
- Ethernet: W5500（SPI0）

PCがマイコンのTCPポートへ接続して送信したデータは、Wi-SUNのUDPパケットとしてスマートメーターへ送信されます。スマートメーターから受信したデータは、TCP接続が存在する場合だけPCへ転送され、接続がない場合は破棄されます。

## 配線

### W5500

- SPI0 SCK: GPIO18
- SPI0 MOSI: GPIO19
- SPI0 MISO: GPIO16
- CS: GPIO17
- INT: GPIO21
- RESET: GPIO20

### MB-RL7023-11

- UART0 TX: GPIO0
- UART0 RX: GPIO1
- RESET: GPIO15

## 必要なもの

- Rust toolchain（`rust-toolchain.toml`に従う）
- `cargo-embed`
- Raspberry Pi Debug Probe
- W5500-EVB-Pico、MB-RL7023-11、スマートメーター
- PCとW5500を同一の`192.168.200.0/24`ネットワークへ接続

Debug Probeのファームウェアが古い場合は、probe-rsが要求するバージョンへ更新してください。

## ビルドと書き込み

プロジェクトのルートで実行します。

```sh
cargo check --target thumbv6m-none-eabi
cargo run
```

`cargo run`は`.cargo/config.toml`のrunner設定により、`cargo embed`でRP2040へ書き込み、RTTログを表示します。ログは`logs/`にも保存されます。

## 瞬時電力の確認

ファームウェア起動後、PCから次を実行すると、ECHONET Liteの瞬時電力計測値（EPC `0xE7`）を取得できます。

```sh
python3 tools/check_smart_meter.py
```

接続先を変更する場合は、次のオプションを使用します。

```sh
python3 tools/check_smart_meter.py --host 192.168.200.200 --port 3610 --timeout 30
```

成功すると、次のようにワット単位で表示されます。

```text
OK: smart meter instantaneous power = 460 W
```

## ログによる確認

次のログが出れば、主要な初期化が完了しています。

- `W5500: initialized`
- `network: configured as 192.168.200.200/24`
- `Wi-SUN: PANA authentication completed`
- `TCP: listening on port 3610`
- `bridge: TCP <-> Wi-SUN forwarding started`

通信異常が明らかな場合は、ファームウェアを再書き込みする前にW5500-EVB-Pico、Wi-SUNモジュール、Debug Probeの電源と配線を確認し、必要に応じて端末と基板を再起動してください。

## 異常時の自動復旧

通信中にWi-SUNモジュールから期待した応答が返らない場合、RP2040側でタイムアウトを検出してWi-SUNモジュールを自動的に再起動します。対象はRP2040本体ではなく、GPIO15に接続されたWi-SUNモジュールです。

- `SKSENDTO` の応答が5秒以内にない場合
- パケット送信後、スマートメーターからの `ERXUDP` 応答が5秒以内にない場合
- PANA認証が60秒以内に完了しない場合
- UARTエラーや受信パケットの解析エラーが発生した場合

異常を検出すると、RESETピンをLOWに1秒保持してからHIGHに戻し、UART受信キューの古いデータを破棄したうえでPANA認証を再実行します。再接続は最大3回試行します。復旧中はPC側のTCP接続がタイムアウトすることがありますが、ログに `Wi-SUN: PANA authentication completed` が出た後に確認スクリプトを再実行してください。

3回試行しても復旧できない場合は、ファームウェアが無限にリセットを繰り返さず、`Wi-SUN: recovery failed; please restart the microcontroller and smart-meter path` を出力して停止します。この場合はマイコン、Wi-SUNモジュール、スマートメーターの電源・配線を確認して再起動してください。

## 認証情報

Wi-SUNのBルート認証情報は`src/broute_credential.rs`にあります。実際の認証情報を含むファイルを公開リポジトリへコミットしないでください。

## ライセンス

ライセンスについては[LICENSE](LICENSE)を参照してください。
第三者コードのライセンス表示は[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)を参照してください。
