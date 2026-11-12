var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
{
    options.AddPolicy("Spa", policy =>
        // ruleid: ASP-CORS-CREDENTIALS-ANY-ORIGIN
        policy.SetIsOriginAllowed(_ => true)
              .AllowAnyHeader()
              .AllowCredentials());
});
var app = builder.Build();
app.UseCors("Spa");
app.Run();
