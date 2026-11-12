using Microsoft.Extensions.Logging;

public class AuthService
{
    private readonly ILogger<AuthService> _logger;

    public AuthService(ILogger<AuthService> logger) => _logger = logger;

    public void Reset(string userId, string reason)
    {
        _logger.LogWarning("Password reset requested for user {UserId}", userId);
        _logger.LogInformation("Token validation failed: {Reason}", reason);
    }
}
