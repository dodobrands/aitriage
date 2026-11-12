public static class Db
{
    // ruleid: ASP-CONN-STRING
    private const string Conn = "Host=db;Database=app;Username=app;Password=P@ss__JOIN__w0rd123";

    public static string ConnectionString => Conn;
}
