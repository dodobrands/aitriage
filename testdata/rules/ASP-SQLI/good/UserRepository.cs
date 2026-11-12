using System.Data;
using Dapper;
using Microsoft.EntityFrameworkCore;

public class UserRepository
{
    private readonly AppDbContext _db;

    public UserRepository(AppDbContext db) => _db = db;

    public List<User> ByName(string name) =>
        _db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}").ToList();

    public List<User> ByEmail(string email) =>
        _db.Users.FromSql($"SELECT * FROM Users WHERE Email = {email}").ToList();

    public List<User> ById(int id) =>
        _db.Users.FromSqlRaw("SELECT * FROM Users WHERE Id = {0}", id).ToList();

    public Task<IEnumerable<Order>> Orders(IDbConnection conn, string customer) =>
        conn.QueryAsync<Order>("SELECT * FROM Orders WHERE Customer = @customer", new { customer });
}
