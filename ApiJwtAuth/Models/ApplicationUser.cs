namespace ApiJwtAuth.Models;

public class ApplicationUser
{
    public string Username { get; init; }

    public string Password { get; init; }

    public string Email { get; init; }

    public string Role { get; set; }

}
