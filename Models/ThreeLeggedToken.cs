using System.Runtime.Serialization;
using System.Text.Json.Serialization;

public class ThreeLeggedToken
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

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; }
}