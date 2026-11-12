using Microsoft.Data.SqlClient;

public class LegacyDao
{
    public SqlCommand ById(SqlConnection conn, string id)
    {
        // ruleid: ASP-SQLI
        return new SqlCommand("SELECT * FROM Users WHERE Id = " + id, conn);
    }
}
