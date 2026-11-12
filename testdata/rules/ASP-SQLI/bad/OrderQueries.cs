using System.Data;
using Dapper;

public class OrderQueries
{
    public Task<IEnumerable<Order>> ForCustomer(IDbConnection conn, string customer)
    {
        // ruleid: ASP-SQLI
        return conn.QueryAsync<Order>("SELECT * FROM Orders WHERE Customer = '" + customer + "'");
    }
}
