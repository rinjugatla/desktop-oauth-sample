# OAuth 2.0 + PKCE 認証サンプル

このプロジェクトは、**デスクトップアプリケーション**（コンソールアプリ）における **OAuth 2.0 Authorization Code Flow w/ PKCE** (Proof Key for Code Exchange) の実装方法を示すサンプルコードです。

.NET 9.0 を使用し、特に **Google API** の認証フローを想定して構成されていますが、基本的な仕組みは他の OAuth 2.0 プロバイダーでも応用可能です。

## 機能・特徴

* **PKCE 対応**: 公開クライアント（デスクトップアプリなど）で推奨されるセキュリティ対策である PKCE を実装し、認可コード横取り攻撃を防ぎます。
* **ローカルサーバー**: 認証後のリダイレクトを受け取るために、一時的なローカル HTTP サーバー (`HttpListener`) を動的にポート割り当てて起動します。
* **User Secrets**: 機密情報（クライアントID、シークレット）をソースコードに埋め込まず、安全に管理する仕組みを使用しています。

## 前提条件

* [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
* Visual Studio Code または Visual Studio 2022

## セットアップ手順

### 1. プロジェクトの準備

リポジトリをクローンし、ディレクトリに移動します。

```bash
git clone <repository-url>
cd desktop-oauth-sample
```

### 2. OAuth クライアント情報の取得 (Google Cloud Console の例)

1. [Google Cloud Console](https://console.cloud.google.com/) にアクセスし、プロジェクトを作成します。
2. 「API とサービス」 > 「**OAuth 同意画面**」を設定します。
3. 「API とサービス」 > 「認証情報」 > 「認証情報を作成」 > 「**OAuth クライアント ID**」を選択します。
4. アプリケーションの種類で「**デスクトップ アプリ**」を選択して作成します。
5. 作成後、「**JSON をダウンロード**」をクリックして、認証情報ファイル（例: `client_secret_XXXX.json`）を保存します。

### 3. ユーザーシークレット (User Secrets) の設定

このサンプルでは、認証情報をソースコードにハードコーディングせず、**User Secrets** 機能を使って管理しています。
ダウンロードした JSON ファイルの内容を、ローカルの秘密情報ストアに登録します。

#### 手順

プロジェクトのルートディレクトリ（`desktop-oauth-sample.csproj` がある場所）で、以下のコマンドを実行してシークレット ID を初期化します。

```bash
dotnet user-secrets init
```

次に、ダウンロードした JSON ファイルの中身を確認してください。通常、以下のような構造になっています。

```json
{
  "installed": {
    "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
    "project_id": "your-project-id",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "YOUR_CLIENT_SECRET",
    "redirect_uris": [
      "http://localhost"
    ]
  }
}
```

この内容をそのまま `secrets.json` に設定します。以下のコマンドを使うと便利です（PowerShell の場合）。

```powershell
Get-Content "path\to\client_secret_XXXX.json" | dotnet user-secrets set
```

または、手動で以下のコマンドを使って個別に設定することも可能ですが、JSON全体を登録するのが一番簡単です。

```bash
# JSONファイルの内容を標準入力から渡して設定 (Bash/Zsh等の場合)
cat path/to/client_secret_XXXX.json | dotnet user-secrets set
```

※ `secrets.json` の実体はユーザープロファイルディレクトリに保存されます。

## 実行方法

セットアップが完了したら、以下のコマンドでアプリケーションを実行します。

```bash
dotnet run
```

### 実行後の挙動

1. コンソールに「ブラウザを起動して認証を行います...」と表示され、デフォルトのブラウザが開きます。
2. Google アカウントでのログインと、アプリへのアクセス許可を求められます。
3. 「許可」すると、ブラウザに `Authentication successful!` と表示されます。
4. コンソールに戻ると、取得した **Access Token** などの情報が表示されます。

## セキュリティ対策

このサンプルアプリケーションには、以下のセキュリティ対策が実装されています：

### 実装済みのセキュリティ機能

* ✅ **PKCE (Proof Key for Code Exchange)**: 認可コード横取り攻撃を防止
* ✅ **State パラメータ**: CSRF（クロスサイトリクエストフォージェリ）攻撃を防止
* ✅ **User Secrets**: クライアントIDとシークレットをソースコードに埋め込まない
* ✅ **ローカルホスト リダイレクト**: セキュアなリダイレクトURI（127.0.0.1使用）
* ✅ **包括的なエラーハンドリング**: OAuthエラーの適切な処理
* ✅ **機密情報の保護**: Code Verifierや認可コードをログに出力しない

### セキュリティ分析レポート

詳細なセキュリティ分析結果と実装内容については、[SECURITY_REPORT.md](SECURITY_REPORT.md)をご参照ください。

**セキュリティ検証結果**:
- CodeQL スキャン: ✅ 脆弱性0件
- コードレビュー: ✅ 指摘事項0件
- OAuth 2.0 ベストプラクティス: ✅ 準拠
