using System.Diagnostics;
using System.Net;
using System.Text;
using desktop_oauth_sample;

class Program
{
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

        string codeVerifier = OAuthHelper.GenerateCodeVerifier();
        string codeChallenge = OAuthHelper.GenerateCodeChallenge(codeVerifier);

        Console.WriteLine($"[PKCE] Code Verifier (生成): {codeVerifier}");
        Console.WriteLine($"[PKCE] Code Challenge (S256ハッシュ): {codeChallenge}");

        // 2. リダイレクトURI用にローカルの空きポートを探してHTTPリスナーを作成
        // 解説:
        // 認証後のコールバックを受け取るために、一時的なローカルサーバーを立ち上げます。
        // ポートを0に指定してTcpListenerを開始すると、OSが空いているポートを割り当ててくれます。
        string redirectUri = OAuthHelper.GenerateRedirectUri();
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
        string authorizationUrl = OAuthHelper.GenerateAuthorizationUrl(codeChallenge, redirectUri);
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
        await OAuthHelper.ExchangeCodeForTokenAsync(authorizationCode, codeVerifier, redirectUri);

        Console.WriteLine("処理が完了しました。何かキーを押すと終了します。");
        Console.ReadKey();
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
}
