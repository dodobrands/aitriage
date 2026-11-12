using Microsoft.Extensions.Logging;

public class AuthService
{
    private readonly ILogger<AuthService> _logger;

    public AuthService(ILogger<AuthService> logger) => _logger = logger;

    public void Login(string user, string password)
    {
        // ruleid: ASP-LOGGING-SENSITIVE
        _logger.LogInformation("Login attempt {User} with {Password}", user, password);
    }
}
