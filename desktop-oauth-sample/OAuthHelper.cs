using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace desktop_oauth_sample
{
    internal class OAuthHelper
    {
        private string ClientId { get; set; }
        private string ProjectId { get; set; }
        private string AuthUri { get; set; }
        private string TokenUri { get; set; }
        private string AuthProviderX509CertUrl { get; set; }
        private string ClientSecret { get; set; }
        private List<string> RedirectUris { get; set; } = new List<string>();
        public string Scope => "openid email profile";
        public string RedirectUri { get; private set; }
        public string CodeVerifier { get; private set; }
        public string CodeChallenge { get; private set; }
        public string State { get; private set; }

        public OAuthHelper()
        {
            var config = new ConfigurationBuilder()
                .AddUserSecrets<Program>() // ユーザーシークレットを読み込む
                .Build();

            ClientId = config["installed:client_id"];
            ProjectId = config["installed:project_id"];
            AuthUri = config["installed:auth_uri"];
            TokenUri = config["installed:token_uri"];
            AuthProviderX509CertUrl = config["installed:auth_provider_x509_cert_url"];
            ClientSecret = config["installed:client_secret"];
            RedirectUris = config.GetSection("installed:redirect_uris")
                .GetChildren()
                .Select(x => x.Value)
                .Where(x => !string.IsNullOrEmpty(x))
                .ToList();

            RedirectUri = GenerateRedirectUri();
            CodeVerifier = GenerateCodeVerifier();
            CodeChallenge = GenerateCodeChallenge(CodeVerifier);
            State = GenerateState();
        }

        /// <summary>
        /// ランダムなローカルポートを使用してリダイレクトURIを生成
        /// </summary>
        private string GenerateRedirectUri()
        {
            var url = $"http://127.0.0.1:{GetRandomUnusedPort()}/";
            return url;
        }

        /// <summary>
        /// Code Verifierを生成する (43〜128文字のランダムな文字列)
        /// </summary>
        private string GenerateCodeVerifier()
        {
            const int length = 128; // Code Verifierの長さ (43-128文字)
            using var rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return Base64UrlEncode(bytes);
        }

        /// <summary>
        /// State パラメータを生成する (CSRF攻撃を防ぐためのランダムな文字列)
        /// </summary>
        private string GenerateState()
        {
            const int length = 32; // 十分なエントロピーを持つ256ビット（32バイト）のランダム値
            using var rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return Base64UrlEncode(bytes);
        }

        /// <summary>
        /// Code Challengeを生成する (VerifierをSHA256ハッシュし、Base64Urlエンコード)
        /// </summary>
        private string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            byte[] challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
            return Base64UrlEncode(challengeBytes);
        }

        /// <summary>
        /// Base64URLエンコード処理
        /// 解説: 通常のBase64に含まれる '+', '/', '=' はURLで特別な意味を持つため置換・削除が必要
        /// </summary>
        private string Base64UrlEncode(byte[] input)
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
        private int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        /// <summary>認証URLを生成</summary>
        /// <returns>認証URL</returns>
        public string GenerateAuthorizationUrl()
        {
            var queryParams = new Dictionary<string, string>
            {
                { "response_type", "code" },
                { "client_id", ClientId },
                { "redirect_uri", RedirectUri },
                { "scope", Scope },
                { "code_challenge", CodeChallenge },
                { "code_challenge_method", "S256" },
                { "state", State }
            };

            var queryString = string.Join("&", queryParams.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
            string authorizationUrl = $"{AuthUri}?{queryString}";
            return authorizationUrl;
        }

        /// <summary>
        /// OAuthコールバックのパラメータを検証する
        /// </summary>
        /// <param name="queryString">コールバックのクエリパラメータ</param>
        /// <param name="authorizationCode">認可コード（出力パラメータ）</param>
        /// <param name="errorMessage">エラーメッセージ（出力パラメータ）</param>
        /// <returns>検証が成功した場合はtrue、失敗した場合はfalse</returns>
        public bool ValidateCallback(System.Collections.Specialized.NameValueCollection queryString, out string? authorizationCode, out string? errorMessage)
        {
            authorizationCode = null;
            errorMessage = null;

            // OAuthエラーのチェック
            var error = queryString["error"];
            if (!string.IsNullOrEmpty(error))
            {
                var errorDescription = queryString["error_description"];
                errorMessage = string.IsNullOrEmpty(errorDescription) 
                    ? $"OAuth エラー: {error}" 
                    : $"OAuth エラー: {error} - {errorDescription}";
                return false;
            }

            // Stateパラメータの検証（CSRF攻撃対策）
            var receivedState = queryString["state"];
            if (string.IsNullOrEmpty(receivedState) || receivedState != State)
            {
                errorMessage = "認証セッションの検証に失敗しました。もう一度お試しください。";
                return false;
            }

            // 認可コードの取得
            authorizationCode = queryString["code"];
            if (string.IsNullOrEmpty(authorizationCode))
            {
                errorMessage = "認可コードが取得できませんでした。";
                return false;
            }

            return true;
        }

        /// <summary>
        /// 認可コードを使ってアクセストークンを取得する
        /// </summary>
        public async Task ExchangeCodeForTokenAsync(string code)
        {
            try
            {
                using var httpClient = new HttpClient();
                var requestData = GenerateTokenRequestData(code, CodeVerifier, RedirectUri);
                var response = await httpClient.PostAsync(TokenUri, requestData);
                response.EnsureSuccessStatusCode();
                var responseContent = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("--------------------------------------------------");
                    Console.WriteLine("トークン取得に成功しました！");

                    try
                    {
                        // JSONを整形して表示
                        //using var doc = JsonDocument.Parse(responseContent);
                        //var formattedJson = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
                        //Console.WriteLine(formattedJson);
                        Console.WriteLine("トークン情報は機密情報のため表示しません。\n表示が必要な場合は上記コードのコメントを解除してください。");
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

        /// <summary>
        /// アクセストークン取得用のリクエストデータを生成
        /// </summary>
        /// <param name="authorizationCode">認可コード</param>
        /// <param name="codeVerifier">PKCEのコードベリファイア</param>
        /// <param name="redirectUri">リダイレクトURI</param>
        /// <returns>アクセストークン取得用のリクエストデータ</returns>
        private FormUrlEncodedContent GenerateTokenRequestData(string authorizationCode, string codeVerifier, string redirectUri)
        {
            var requestData = new Dictionary<string, string>
            {
                { "code", authorizationCode },
                { "client_id", ClientId },
                { "client_secret", ClientSecret },
                { "redirect_uri", redirectUri },
                { "grant_type", "authorization_code" },
                { "code_verifier", codeVerifier }
            };
            return new FormUrlEncodedContent(requestData);
        }
    }
}
