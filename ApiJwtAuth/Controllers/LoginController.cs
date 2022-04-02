using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ApiJwtAuth.DTOs;
using ApiJwtAuth.Models;
using ApiJwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using static BCrypt.Net.BCrypt;

namespace ApiJwtAuth.Controllers;

[ApiController()]
[Route("[controller]")]
public class LoginController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly UserRepo _users;
    private readonly RegisterService _registerService;

    public LoginController(IConfiguration config, UserRepo users, RegisterService registerService)
    {
        _config = config;
        _users = users;
        _registerService = registerService;
    }

    [AllowAnonymous]
    [HttpPost()]
    public IActionResult Auth([FromBody] AuthRequestDto login)
    {
        var user = Authenticate(login);
        if (user is null) return NotFound();
        if (!user.Verified) return Conflict("Email not verified");

        string token = GenerateToken(user);
        return Ok(token);
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterDto registerDto)
    {
        if (_users.Find(u => u.Username == registerDto.Username).Any())
            return Conflict("Username already taken");
        if (_users.Find(u => u.Email == registerDto.Email).Any())
            return Conflict("Email already taken");

        _registerService.Register(registerDto);
        return Ok();
    }

    [AllowAnonymous]
    [HttpPost("verify")]
    public IActionResult VerifyEmail(string token)
    {
        ApplicationUser? user = _registerService.VerifyEmailToken(token);
        if (user is null)
            return BadRequest();
        if (user.Verified)
            return Conflict("Already verified");

        user.Verified = true;
        user.Role = "User";
        return Ok();
    }

    private string GenerateToken(ApplicationUser user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var token = new JwtSecurityToken(_config["Jwt:Issuer"],
            _config["Jwt:Audience"],
            claims,
            expires: DateTime.Now,//.AddMinutes(15),
            signingCredentials: signingCredentials
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private ApplicationUser? Authenticate(AuthRequestDto login)
    {
        ApplicationUser? user = _users.FindByUsername(login.Username);
        if (user is null)
            return null;

        if (Verify(login.Password, user.PasswordHash))
            return user;

        return null;
    }
}
