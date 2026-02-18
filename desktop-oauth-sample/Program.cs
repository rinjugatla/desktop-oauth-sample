using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
// using System.Web; // 不要


class Program
{
    // ==========================================
    // OAuth 2.0 設定 (GCPなどのプロバイダーから取得した情報)
    // ==========================================
    // 本番環境では、これらの値を環境変数や安全なキーストアから読み込むことが推奨されます。
    // 今回は学習用サンプルとして定数に定義します。
    
    // クライアントID (GCP Consoleで作成したOAuth 2.0 クライアントID)
    const string ClientId = "YOUR_CLIENT_ID";
    
    // クライアントシークレット (デスクトップアプリの場合、シークレットの安全な保管は難しいため、
    // PKCEを使用することでセキュリティを高めますが、プロバイダーによっては必要な場合があります)
    const string ClientSecret = "YOUR_CLIENT_SECRET"; 

    // 認可エンドポイント
    const string AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    
    // トークンエンドポイント
    const string TokenEndpoint = "https://oauth2.googleapis.com/token";

    // スコープ (必要な権限を指定します。例: email profile openid)
    const string Scope = "openid email profile";

    static async Task Main(string[] args)
    {
        Console.WriteLine("==================================================");
        Console.WriteLine("OAuth 2.0 + PKCE 認証サンプル (デスクトップアプリ)");
        Console.WriteLine("==================================================");
        Console.WriteLine("処理を開始します...");

        // 1. PKCE (Proof Key for Code Exchange) 用の検証コードとチャレンジを生成
        // 解説:
        // PKCEは、認可コード横取り攻撃を防ぐための仕組みです。
        // デスクトップアプリのようなパブリッククライアントでは、Client Secretを安全に保つことができません。
        // そのため、動的に生成した「Code Verifier」とそれをハッシュ化した「Code Challenge」を使って、
        // 認可リクエストを行ったクライアントと、トークンリクエストを行うクライアントが同一であることを証明します。
        
        string codeVerifier = GenerateCodeVerifier();
        string codeChallenge = GenerateCodeChallenge(codeVerifier);

        Console.WriteLine($"[PKCE] Code Verifier (生成): {codeVerifier}");
        Console.WriteLine($"[PKCE] Code Challenge (S256ハッシュ): {codeChallenge}");

        // 2. リダイレクトURI用にローカルの空きポートを探してHTTPリスナーを作成
        // 解説:
        // 認証後のコールバックを受け取るために、一時的なローカルサーバーを立ち上げます。
        // ポートを0に指定してTcpListenerを開始すると、OSが空いているポートを割り当ててくれます。
        string redirectUri = $"http://127.0.0.1:{GetRandomUnusedPort()}/";
        Console.WriteLine($"[Redirect URI] {redirectUri}");
        
        using var httpListener = new HttpListener();
        httpListener.Prefixes.Add(redirectUri);
        httpListener.Start();

        // 3. 認可リクエストURLの作成
        // 解説:
        // ユーザーをブラウザへ誘導するためのURLを作成します。
        // ここで code_challenge と code_challenge_method=S256 を含めるのがPKCEの肝です。

        // System.Web.HttpUtilityを使わずに手動でクエリパラメータを構築
        // (コンソールアプリで追加パッケージなしで動作させるため)
        var queryParams = new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "client_id", ClientId },
            { "redirect_uri", redirectUri },
            { "scope", Scope },
            { "code_challenge", codeChallenge },
            { "code_challenge_method", "S256" }
        };

        var queryString = string.Join("&", queryParams.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
        string authorizationUrl = $"{AuthorizationEndpoint}?{queryString}";
        
        Console.WriteLine("ブラウザを起動して認証を行います...");

        // ブラウザを開く
        OpenBrowser(authorizationUrl);

        // 4. 認可コードの受け取り
        // 解説:
        // ユーザーがブラウザで認証・同意を行うと、指定した redirect_uri にリダイレクトされます。
        // そのURLパラメータに付与された認可コード (code) をローカルサーバーで受け取ります。
        var context = await httpListener.GetContextAsync();
        var response = context.Response;
        
        // ブラウザに完了メッセージを表示
        string responseString = "<html><body><h2>Authentication successful!</h2><p>You can close this tab and return to the application.</p></body></html>";
        byte[] buffer = Encoding.UTF8.GetBytes(responseString);
        response.ContentLength64 = buffer.Length;
        var responseOutput = response.OutputStream;
        await responseOutput.WriteAsync(buffer, 0, buffer.Length);
        responseOutput.Close();
        httpListener.Stop(); // サーバー停止

        // クエリパラメータから code を抽出
        // リクエストURL: http://127.0.0.1:xxx/?code=AUTHORIZATION_CODE&...
        string? authorizationCode = context.Request.QueryString["code"];
        
        if (string.IsNullOrEmpty(authorizationCode))
        {
            Console.WriteLine("エラー: 認可コードが取得できませんでした。");
            return;
        }

        Console.WriteLine($"[Authorization Code] 取得成功: {authorizationCode}");

        // 5. トークンリクエスト (認可コードとトークンを交換)
        // 解説:
        // 取得した認可コードを使ってアクセストークンをリクエストします。
        // ここで重要なのが code_verifier を送信することです。
        // サーバー側は、最初に受け取った code_challenge と、今送られてきた code_verifier をハッシュ化して比較します。
        // 一致すれば、正当なクライアントからのリクエストであると判断されます。

        Console.WriteLine("トークンをリクエストしています...");
        await ExchangeCodeForTokenAsync(authorizationCode, codeVerifier, redirectUri);

        Console.WriteLine("処理が完了しました。何かキーを押すと終了します。");
        Console.ReadKey();
    }

    /// <summary>
    /// Code Verifierを生成する (43〜128文字のランダムな文字列)
    /// </summary>
    static string GenerateCodeVerifier()
    {
        // 32バイトのランダムデータを生成 (Base64urlエンコードすると約43文字になる)
        // PKCEの仕様では最低43文字必要
        using var rng = RandomNumberGenerator.Create();
        byte[] bytes = new byte[32];
        rng.GetBytes(bytes);
        return Base64UrlEncode(bytes);
    }

    /// <summary>
    /// Code Challengeを生成する (VerifierをSHA256ハッシュし、Base64Urlエンコード)
    /// </summary>
    static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        byte[] challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncode(challengeBytes);
    }

    /// <summary>
    /// Base64URLエンコード処理
    /// 解説: 通常のBase64に含まれる '+', '/', '=' はURLで特別な意味を持つため置換・削除が必要
    /// </summary>
    static string Base64UrlEncode(byte[] input)
    {
        string base64 = Convert.ToBase64String(input);
        // Base64URL仕様への変換:
        // '+' -> '-'
        // '/' -> '_'
        // '=' (パディング) -> 削除
        return base64.Replace("+", "-").Replace("/", "_").Replace("=", "");
    }

    /// <summary>
    /// 空いているローカルポートを取得する
    /// </summary>
    static int GetRandomUnusedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>
    /// OSのデフォルトブラウザでURLを開く
    /// </summary>
    static void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            // 環境によってはブラウザが開けない場合があるため、コンソールにURLを表示
            Console.WriteLine("ブラウザを自動で開けませんでした。以下のURLを手動で開いてください:");
            Console.WriteLine(url);
            Console.WriteLine($"エラー詳細: {ex.Message}");
        }
    }

    /// <summary>
    /// 認可コードを使ってアクセストークンを取得する
    /// </summary>
    static async Task ExchangeCodeForTokenAsync(string code, string codeVerifier, string redirectUri)
    {
        using var client = new HttpClient();
        
        var requestBody = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("client_id", ClientId),
            new KeyValuePair<string, string>("code_verifier", codeVerifier), // PKCEで重要！
            new KeyValuePair<string, string>("client_secret", ClientSecret), // 必要に応じて
            new KeyValuePair<string, string>("scope", ""),
            new KeyValuePair<string, string>("grant_type", "authorization_code")
        });

        try
        {
            var response = await client.PostAsync(TokenEndpoint, requestBody);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("--------------------------------------------------");
                Console.WriteLine("トークン取得に成功しました！");
                
                // JSONを整形して表示
                try 
                {
                    using var doc = JsonDocument.Parse(responseContent);
                    var formattedJson = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
                    Console.WriteLine(formattedJson);
                }
                catch
                {
                    Console.WriteLine(responseContent);
                }
                Console.WriteLine("--------------------------------------------------");
            }
            else
            {
                Console.WriteLine($"トークン取得エラー: {response.StatusCode}");
                Console.WriteLine(responseContent);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"通信エラーが発生しました: {ex.Message}");
        }
    }
}

