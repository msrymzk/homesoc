# Malcolm Network Monitor

家庭内ネットワークに導入されているトラフィック監視システム「[Malcolm](https://github.com/cisagov/Malcolm)」のデータを活用し、ネットワークの異常検知と定期レポート送信を自動化するPythonスクリプトです。

Malcolmに内蔵されているOpenSearch APIへ定期的にクエリを発行し、検知した情報をSlack等のWebhook経由で通知します。

## 機能一覧

本スクリプトは引数 (`--mode`) によって以下の3つの機能を提供します。

1. **脅威検知アラート (`--mode alerts`)**
   - 過去15分間のSuricataログを解析し、重要度（Severity）がHighの重大なセキュリティアラートを即時通知します。
   - 大量のアラートによるスパム化を防ぐため、送信元IPとアラート名で集約して通知します。

2. **未知デバイス検知 (`--mode new_devices`)**
   - 過去1時間分の通信ログからアクティブなIPアドレスを抽出し、過去の接続履歴 (`known_devices.json`) と照合します。
   - 初めてネットワークに参加した（通信を行った）未知のIPアドレスを発見した場合に警告を通知します。

3. **日次サマリーレポート (`--mode daily_summary`)**
   - 過去24時間の全トラフィックデータを集計し、以下のサマリーを通知します。
     - 1日の総通信量 (GB/MB)
     - アクティブデバイス総数
     - HTTPエラー発生件数 (4xx/5xx を分離して集計)
     - DNS NXDOMAIN エラー件数
     - アクセス先の国別ランキング (上位10カ国)
     - 使用プロトコルの割合 (上位10プロトコル)
     - 合計通信バイト数が最も多い端末 (トップトーカー上位50件)
     - 脅威アラート検知数とその内訳 (High/Medium, 上位10件)

**💡 DHCPホスト名マッピング（全モード共通）**
各モードの実行時、スクリプトは自動的に直近24時間のDHCPログを解析し、IPアドレスとホスト名の紐付けテーブル（`ip_to_host.json`）を生成・更新します。これにより、通知メッセージ内のIPアドレスが自動的に `iPhone (192.168.100.25)` のように分かりやすく表示されます。

## 動作環境・必須要件

* Python 3.10 以上
* **uv** (高速なPythonパッケージ・プロジェクト管理ツール)

## セットアップ

1. **環境変数の設定**
   ディレクトリ内にある `.env.example` をコピーして `.env` ファイルを作成し、ご自身の環境に合わせて設定を入力してください。

   ```bash
   cp .env.example .env
   ```

   **`.env` の設定項目:**
   * `MALCOLM_OPENSEARCH_URL`: MalcolmのOpenSearch APIエンドポイント（通常は `https://<MALCOLM_IP>/mapi/opensearch`）
   * `MALCOLM_USER`: Malcolmのログインユーザー名
   * `MALCOLM_PASS`: Malcolmのログインパスワード
   * `WEBHOOK_URL`: 通知先のSlack等 Webhook URL

2. **依存関係のインストール（不要）**
   本プロジェクトは `uv` を使用して管理されているため、手動でパッケージをインストールする必要はありません。`uv run` を実行した際に自動で仮想環境が構築されます。

## 実行方法

任意のモードを指定してスクリプトを実行します。

```bash
# 脅威アラートの確認
uv run python malcolm_monitor.py --mode alerts

# 未知デバイスの確認
uv run python malcolm_monitor.py --mode new_devices

# 日次サマリーの送信
uv run python malcolm_monitor.py --mode daily_summary
```

## 定期実行 (cron) の設定例

OSの `cron` を用いて、各機能を定期実行する場合の設定例です。
`crontab -e` 等で追記してください。（`/Users/yama/Documents/src/homesoc` の部分は実際のスクリプト配置ディレクトリに合わせて変更してください）

```bash
# 機能A: 脅威検知アラートを15分ごとに実行
*/15 * * * * cd /Users/yama/Documents/src/homesoc && uv run python malcolm_monitor.py --mode alerts

# 機能B: 未知のデバイス検知を1時間ごとに実行
0 * * * * cd /Users/yama/Documents/src/homesoc && uv run python malcolm_monitor.py --mode new_devices

# 機能C: デイリーサマリーレポートを毎日 23:59 に実行
59 23 * * * cd /Users/yama/Documents/src/homesoc && uv run python malcolm_monitor.py --mode daily_summary
```

## 運用上の注意点

* スクリプトは自己署名証明書環境（Malcolmデフォルト）で動作するように、HTTPSの証明書検証をスキップ (`verify=False`) する仕様となっています。
* `new_devices` モードの判定に使用する学習データは、初回実行時にすべて「新規」として扱われ、`known_devices.json` に保存されます。誤検知のIPや不要なIPは、このJSONファイルを手動で編集することで調整可能です。
