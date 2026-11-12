using System.ComponentModel.DataAnnotations;

public class SmtpSettings
{
    public const string ApiKeyHeaderName = "X-Api-Key";

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = "";

    public string SecretName()
    {
        var secretName = "orders-db-connection";
        return secretName;
    }
}
