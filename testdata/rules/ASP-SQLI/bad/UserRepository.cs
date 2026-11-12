using Microsoft.EntityFrameworkCore;

public class UserRepository
{
    private readonly AppDbContext _db;

    public UserRepository(AppDbContext db) => _db = db;

    public List<User> ByName(string name)
    {
        // ruleid: ASP-SQLI
        return _db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'").ToList();
    }
}
