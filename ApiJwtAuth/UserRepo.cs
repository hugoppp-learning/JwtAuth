using ApiJwtAuth.DTOs;
using ApiJwtAuth.Models;
using static BCrypt.Net.BCrypt;

namespace ApiJwtAuth;

public class UserRepo
{
    private static List<ApplicationUser> _users = new()
    {
        new ApplicationUser()
            { Role = "Admin", Username = "vlad", Email = "vlad@gmail.com", PasswordHash = HashPassword("veryStronk"), Verified = true},
        new ApplicationUser()
            { Role = "User", Username = "therock", Email = "therock@gmail.com", PasswordHash = HashPassword("moreStronk:0") }
    };

    public ApplicationUser? FindByUsername(string username)
    {
        return _users.Find(u => u.Username == username);
    }

    public IEnumerable<ApplicationUser> GetAll()
    {
        return _users;
    }

    public IEnumerable<ApplicationUser> Find(Func<ApplicationUser, bool> predicate)
    {
        return _users.Where(predicate);
    }

    public void Add(ApplicationUser user)
    {
        _users.Add(user);
    }
}
