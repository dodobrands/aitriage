using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication().AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        // ruleid: ASP-JWT-VALIDATION-DISABLED
        ValidateLifetime = false,
        RequireSignedTokens = false,
    };
});
var app = builder.Build();
app.Run();
