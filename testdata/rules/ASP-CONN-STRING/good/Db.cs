using Microsoft.Extensions.Configuration;

public static class Db
{
    // Example only: "Server=localhost;Password=changeme"
    public static string Build(string host, string password) =>
        $"Server={host};Database=app;User Id=app;Password={password};";

    public static string FromConfig(IConfiguration config) => config.GetConnectionString("Default");
}
