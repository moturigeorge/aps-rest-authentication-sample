using System.Text.Json.Serialization;

namespace aps_rest_authentication_sample.Models
{
    public class TwoLeggedToken
    {
        private int? _expiresIn;

        private long? _expiresAt;

        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }

        [JsonPropertyName("expires_at")]
        public long? ExpiresAt => _expiresAt;

        [JsonPropertyName("expires_in")]
        public int? ExpiresIn
        {
            get
            {
                return _expiresIn;
            }
            set
            {
                _expiresIn = value;
                _expiresAt = DateTimeOffset.Now.ToUnixTimeSeconds() + ExpiresIn;
            }
        }
    }
}
