namespace aps_rest_authentication_sample.Models
{
    public class ForgeConfiguration
    {
        public Forge Forge { get; set; }
    }
    public class Forge
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Callback { get; set; }
    }
}