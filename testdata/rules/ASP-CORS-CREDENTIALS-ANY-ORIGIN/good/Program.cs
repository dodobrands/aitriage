var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
{
    options.AddPolicy("Spa", policy =>
        policy.WithOrigins("https://app.example.com")
              .AllowAnyHeader()
              .AllowCredentials());
    options.AddPolicy("Tenants", policy =>
        policy.SetIsOriginAllowed(origin => new Uri(origin).Host.EndsWith(".example.com"))
              .AllowCredentials());
});
var app = builder.Build();
app.UseCors("Spa");
app.Run();
