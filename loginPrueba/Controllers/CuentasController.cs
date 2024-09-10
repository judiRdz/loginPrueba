using loginPrueba.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace loginPrueba.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IConfiguration configuration;

        public CuentasController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.configuration = configuration;
        }

        private async Task<RespuestaAutenticacion> ConstruirToken(CredencialesUsuario credencialesUsuario)
        {
            var claims = new List<Claim>()
            {
                new Claim("email", credencialesUsuario.Email)
            };

            var usuario = await userManager.FindByEmailAsync(credencialesUsuario.Email);
            var claimsRoles = await userManager.GetClaimsAsync(usuario!);

            claims.AddRange(claimsRoles);

            var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["LlaveJWT"]!));
            var creds = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);

            var expiracion = DateTime.Now.AddDays(1);

            var securityToken = new JwtSecurityToken(issuer: null, audience: null, claims: claims, expires: expiracion, signingCredentials: creds);

            return new RespuestaAutenticacion
            {
                Token = new JwtSecurityTokenHandler().WriteToken(securityToken),
                Expiracion = expiracion,
            };
        }

        [HttpGet("RenovarToken")]
        [Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult<RespuestaAutenticacion>> Renovar()
        {
            var emailClaims = HttpContext.User.Claims.Where(x => x.Type == "email").FirstOrDefault();
            var credencialesUsuario = new CredencialesUsuario()
            {
                Email = emailClaims!.Value
            };
            return await ConstruirToken(credencialesUsuario);
        }

        [HttpPost("Registrar")]
        public async Task<ActionResult<RespuestaAutenticacion>> Registrar(CredencialesUsuario credencialesUsuario)
        {
            var usuario = new IdentityUser
            {
                UserName = credencialesUsuario.Email,
                Email = credencialesUsuario.Email
            };

            var resultado = await userManager.CreateAsync(usuario, credencialesUsuario.Password);
            if (resultado.Succeeded)
                return await ConstruirToken(credencialesUsuario);
            return BadRequest(resultado.Errors);
        }

        [HttpPost("Login")]
        public async Task<ActionResult<RespuestaAutenticacion>> Login(CredencialesUsuario credencialesUsuario)
        {
            var resultado = await signInManager.PasswordSignInAsync(
                credencialesUsuario.Email, credencialesUsuario.Password, isPersistent: false, lockoutOnFailure: false);
            if (resultado.Succeeded)
                return await ConstruirToken(credencialesUsuario);

            var error = new Mensaje()
            {
                Error = "Login incorrecto"
            };

            return BadRequest(error);
        }
    }

}
