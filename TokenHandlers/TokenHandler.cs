using aps_rest_authentication_sample.Models;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace aps_rest_authentication_sample.TokenHandlers
{
    public class TokenHandler
    {
        private ForgeConfiguration forgeConfiguration = new ForgeConfiguration();
        public static string refreshToken;
        public TokenHandler(IConfiguration configuration)
        {
            // Bind the configuration section to the ForgeConfiguration class
            forgeConfiguration = configuration.Get<ForgeConfiguration>();

            // Check if the forgeConfiguration is null
            if (forgeConfiguration == null || forgeConfiguration.Forge == null)
            {
                throw new Exception("Failed to bind Forge configuration.");
            }

            // Check if ClientId and ClientSecret are set
            if (string.IsNullOrEmpty(forgeConfiguration.Forge.ClientId) || string.IsNullOrEmpty(forgeConfiguration.Forge.ClientSecret))
            {
                throw new Exception("ClientId or ClientSecret is not set.");
            }
        }


        public async Task<ThreeLeggedToken> _3LAuthenticateAsync()
        {
            try
            {
                // Step 1: Generate Code Verifier and Challenge
                var codeVerifier = GenerateCodeVerifier();
                var codeChallenge = GenerateCodeChallenge(codeVerifier);

                // Step 2: Construct Authorization URL
                var authorizationUrl = $"https://developer.api.autodesk.com/authentication/v2/authorize?" +
                                       $"response_type=code&client_id={forgeConfiguration.Forge.ClientId}&redirect_uri={Uri.EscapeDataString(forgeConfiguration.Forge.Callback)}" +
                                       $"&scope=data:read&code_challenge={codeChallenge}&code_challenge_method=S256";

                // Step 3: Open the default browser to redirect to Autodesk login page
                var file = GetChromeExe();
                string args;
                var userData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "tmp_chrome");
                args = $"/incognito --chrome-frame --user-data-dir={userData} --window-size=540,540 --app={authorizationUrl} --disable-application-cache";
                ProcessStartInfo startInfo = new ProcessStartInfo(file)
                {
                    WindowStyle = ProcessWindowStyle.Minimized,
                    Arguments = args,
                    UseShellExecute = true
                };
                var p = Process.Start(startInfo);


                //Process.Start(new ProcessStartInfo(authorizationUrl) { UseShellExecute = true });

                // Step 4: Listen for Redirect to capture the authorization code
                var authCode = await WaitForAuthorizationCodeAsync();

                // Step 5: Exchange Authorization Code for Access Token
                var _3LTokenResponse = await Get3LAccessTokenAsync(authCode, codeVerifier);
                //var _2LTokenSSResponse = await Get2LAccessTokenAsync();             
                return _3LTokenResponse;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private static string GetChromeExe()
        {
            bool isWindows = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            if (!isWindows)
            {
                return null;
            }
            const string suffix = @"Google\Chrome\Application\chrome.exe";
            var prefixes = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) };
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (programFilesx86 != programFiles)
            {
                prefixes.Add(programFiles);
            }
            else
            {
                if (Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion",
                    "ProgramW6432Dir", null) is string programFilesDirFromReg)
                {
                    prefixes.Add(programFilesDirFromReg);
                }

            }
            prefixes.Add(programFilesx86);
            var path = prefixes.Distinct().Select(prefix => Path.Combine(prefix, suffix)).FirstOrDefault(File.Exists);
            return path;
        }

        private async Task<string> WaitForAuthorizationCodeAsync()
        {
            var listener = new HttpListener();
            try
            {
                // Listen on the redirect URI (localhost) to get the authorization code
                listener.Prefixes.Add(forgeConfiguration.Forge.Callback + "/");
                listener.Start();

                var context = await listener.GetContextAsync();
                var code = context.Request.QueryString["code"];

                // Send a response back to the browser
                var responseString = "<html><body><h2>Login Success</h2><p>You can now close this window!</p></body></html>";
                byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                var response = context.Response;
                response.ContentType = "text/html";
                response.ContentLength64 = buffer.Length;
                response.StatusCode = 200;
                response.OutputStream.Write(buffer, 0, buffer.Length);
                response.OutputStream.Close();
                // Now request the final access_token
                return code;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return null;
            }
            finally
            {
                listener.Stop(); // Ensure that we stop the listener after we're done
            }
        }

        private async Task<ThreeLeggedToken> Get3LAccessTokenAsync(string authorizationCode, string codeVerifier)
        {
            using (var client = new HttpClient())
            {
                var authHeaderValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{forgeConfiguration.Forge.ClientId}:{forgeConfiguration.Forge.ClientSecret}"));
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", authHeaderValue);

                var values = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", authorizationCode },
                { "redirect_uri", forgeConfiguration.Forge.Callback },
                { "code_verifier", codeVerifier }
            };

                var content = new FormUrlEncodedContent(values);
                var response = await client.PostAsync("https://developer.api.autodesk.com/authentication/v2/token", content);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    throw new Exception($"Failed to obtain token: {responseBody}");
                }                  
                return JsonSerializer.Deserialize<ThreeLeggedToken>(responseBody);
            }
        }


        private async Task<TwoLeggedToken> Get2LAccessTokenAsync()
        {
            using (var client = new HttpClient())
            {
                var values = new Dictionary<string, string>
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", forgeConfiguration.Forge.ClientId },
                    { "client_secret", forgeConfiguration.Forge.ClientSecret },
                    { "scope", "account:write data:read account:read" }
                };

                var content = new FormUrlEncodedContent(values);
                var response = await client.PostAsync("https://developer.api.autodesk.com/authentication/v2/token", content);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    throw new Exception($"Failed to obtain token: {responseBody}");
                }
                return JsonSerializer.Deserialize<TwoLeggedToken>(responseBody);
            }
        }


        private static string GenerateCodeVerifier()
        {
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Base64UrlEncode(randomBytes);
        }

        private static string GenerateCodeChallenge(string codeVerifier)
        {
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                return Base64UrlEncode(challengeBytes);
            }
        }

        private static string Base64UrlEncode(byte[] arg)
        {
            return Convert.ToBase64String(arg)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}