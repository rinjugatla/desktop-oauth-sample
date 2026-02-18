using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace desktop_oauth_sample
{
    internal static class OAuthHelper
    {
        private static string ClientId { get; set; }
        private static string ProjectId { get; set; }
        private static string AuthUri { get; set; }
        private static string TokenUri { get; set; }
        private static string AuthProviderX509CertUrl { get; set; }
        private static string ClientSecret { get; set; }
        private static List<string> RedirectUris { get; set; } = new List<string>();
        public static string Scope => "openid email profile";

        static OAuthHelper()
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
        }

        /// <summary>
        /// ランダムなローカルポートを使用してリダイレクトURIを生成
        /// </summary>
        public static string GenerateRedirectUri()
        {
            var url = $"http://127.0.0.1:{GetRandomUnusedPort()}/";
            return url;
        }

        /// <summary>
        /// Code Verifierを生成する (43〜128文字のランダムな文字列)
        /// </summary>
        public static string GenerateCodeVerifier()
        {
            const int length = 128; // Code Verifierの長さ (43-128文字)
            using var rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return Base64UrlEncode(bytes);
        }

        /// <summary>
        /// Code Challengeを生成する (VerifierをSHA256ハッシュし、Base64Urlエンコード)
        /// </summary>
        public static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            byte[] challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
            return Base64UrlEncode(challengeBytes);
        }

        /// <summary>
        /// Base64URLエンコード処理
        /// 解説: 通常のBase64に含まれる '+', '/', '=' はURLで特別な意味を持つため置換・削除が必要
        /// </summary>
        private static string Base64UrlEncode(byte[] input)
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
        private static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        /// <summary>認証URLを生成</summary>
        /// <param name="codeChallenge">PKCEのコードチャレンジ</param>
        /// <param name="redirectUri">リダイレクトURI(ポート番号指定を含む)</param>
        /// <returns>認証URL</returns>
        public static string GenerateAuthorizationUrl(string codeChallenge, string redirectUri)
        {
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
            string authorizationUrl = $"{AuthUri}?{queryString}";
            return authorizationUrl;
        }

        /// <summary>
        /// 認可コードを使ってアクセストークンを取得する
        /// </summary>
        public static async Task ExchangeCodeForTokenAsync(string code, string codeVerifier, string redirectUri)
        {
            try
            {
                using var httpClient = new HttpClient();
                var requestData = GenerateTokenRequestData(code, codeVerifier, redirectUri);
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

        /// <summary>
        /// アクセストークン取得用のリクエストデータを生成
        /// </summary>
        /// <param name="authorizationCode">認可コード</param>
        /// <param name="codeVerifier">PKCEのコードベリファイア</param>
        /// <param name="redirectUri">リダイレクトURI</param>
        /// <returns>アクセストークン取得用のリクエストデータ</returns>
        private static FormUrlEncodedContent GenerateTokenRequestData(string authorizationCode, string codeVerifier, string redirectUri)
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
