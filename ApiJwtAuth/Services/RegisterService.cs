using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ApiJwtAuth.DTOs;
using ApiJwtAuth.Models;
using Microsoft.IdentityModel.Tokens;
using static BCrypt.Net.BCrypt;

namespace ApiJwtAuth.Services;

public class RegisterService
{
    private readonly IConfiguration _config;
    private readonly ILogger<RegisterService> _logger;
    private readonly UserRepo _users;

    private SymmetricSecurityKey SecurityKey => new(Encoding.UTF8.GetBytes(_config["Jwt:EmailVerificationKey"]));

    private SigningCredentials SigningCredentials => new(SecurityKey, SecurityAlgorithms.HmacSha256);

    public RegisterService(IConfiguration config, ILogger<RegisterService> logger, UserRepo users)
    {
        _config = config;
        _logger = logger;
        _users = users;
    }

    public void Register(RegisterDto registerDto)
    {
        string token = CreateToken(registerDto);
        _users.Add(new ApplicationUser()
        {
            Email = registerDto.Email,
            PasswordHash = HashPassword(registerDto.Password),
            Username = registerDto.Username,
            Role = "Unverified"
        });
        _logger.LogInformation("This is send per email: '{EmailVerificationToken}'", token);
    }


    private string CreateToken(RegisterDto registerDto)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Email, registerDto.Email),
            new Claim(ClaimTypes.Name, registerDto.Username)
        };

        var token = new JwtSecurityToken(
            _config["Jwt:Issuer"],
            _config["Jwt:Audience"],
            claims,
            expires: DateTime.Now.AddSeconds(30),
            signingCredentials: SigningCredentials
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ApplicationUser? VerifyEmailToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidIssuer = _config["Jwt:Issuer"],
                ValidAudience = _config["Jwt:Audience"],
                IssuerSigningKey = SecurityKey
            }, out SecurityToken validatedToken);

            var jwtSecurityToken = validatedToken as JwtSecurityToken;
            IEnumerable<Claim> claims = jwtSecurityToken?.Claims.ToArray() ?? throw new Exception();

            string username = claims.First(o => o.Type == ClaimTypes.Name).Value;
            string email = claims.First(o => o.Type == ClaimTypes.Email).Value;

            ApplicationUser? user = _users.FindByUsername(username);
            if (user?.Email == email)
                return user;

            return null;
        }
        catch
        {
            return null;
        }
    }

}
