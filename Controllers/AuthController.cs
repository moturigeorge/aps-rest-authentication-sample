using aps_rest_authentication_sample.TokenHandlers;
using Microsoft.AspNetCore.Mvc;

namespace aps_rest_authentication_sample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly TokenHandler _autodeskOAuth;
        public AuthController(IConfiguration configuration)
        {
            _autodeskOAuth = new TokenHandler(configuration);
        }

        [HttpGet(Name = "Callback")]
        public async Task<ActionResult<ThreeLeggedToken>> Callback()
        {
            var tokenResponse = await _autodeskOAuth._3LAuthenticateAsync();
            return Ok(tokenResponse);
        }
    }

}
