using System.Security.Claims;
using ApiJwtAuth.DTOs;
using ApiJwtAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiJwtAuth.Controllers;

[ApiController()]
[Route("[controller]")]
[Authorize]
public class UserController : ControllerBase
{
    private UserRepo _users;

    public UserController(UserRepo users)
    {
        _users = users;
    }

    [HttpGet("public")]
    [AllowAnonymous]
    public ActionResult Public()
    {
        return Ok("public");
    }

    [HttpGet("current")]
    public ActionResult<ApplicationUserDto> CurrentUser()
    {
        ApplicationUser? user = GetCurrentUser();
        if (user is null)
            return NotFound();

        return new ApplicationUserDto(user);
    }

    [HttpGet("all")]
    [Authorize(Roles = "Admin")]
    public ActionResult<IEnumerable<ApplicationUserDto>> GetAll()
    {
        return _users.GetAll()
            .Select(u => new ApplicationUserDto(u))
            .ToList();
    }

    private ApplicationUser? GetCurrentUser()
    {
        IEnumerable<Claim>? userClaims = (HttpContext.User.Identity as ClaimsIdentity)?.Claims;
        if (userClaims is null) return null;

        IEnumerable<Claim> claims = userClaims.ToList();
        return new ApplicationUser()
        {
            Username = claims.First(o => o.Type == ClaimTypes.Name).Value,
            Email = claims.First(o => o.Type == ClaimTypes.Email).Value,
            Role = claims.First(o => o.Type == ClaimTypes.Role).Value
        };
    }

}
