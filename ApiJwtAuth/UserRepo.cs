using ApiJwtAuth.Models;

namespace ApiJwtAuth;

public class UserRepo
{
    private static List<ApplicationUser> _users = new()
    {
        new ApplicationUser() { Role = "Admin", Username = "vlad", Email = "vlad@gmail.com", Password = "veryStronk" },
        new ApplicationUser() { Role= "User", Username = "therock", Email = "therock@gmail.com", Password = "moreStronk:0" }
    };

    public ApplicationUser? FindByUsername(string username)
    {
        return _users.Find(u => u.Username == username);
    }

    public IEnumerable<ApplicationUser> GetAll()
    {
        return _users;
    }
}
