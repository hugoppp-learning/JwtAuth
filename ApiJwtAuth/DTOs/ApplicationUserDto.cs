using ApiJwtAuth.Models;

namespace ApiJwtAuth.DTOs;

public record ApplicationUserDto(string Username, string Email, string Role)
{
    public ApplicationUserDto(ApplicationUser applicationUser) : this(
        applicationUser.Username,
        applicationUser.Email,
        applicationUser.Role)
    {
    }
};
