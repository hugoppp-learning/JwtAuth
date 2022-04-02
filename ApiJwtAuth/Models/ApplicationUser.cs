namespace ApiJwtAuth.Models;

public class ApplicationUser
{
    public string Username { get; init; } = null!;

    public string PasswordHash { get; init; } = null!;

    public string Email { get; init; } = null!;

    public string Role { get; set; } = null!;

    public bool Verified { get; set; }

}
