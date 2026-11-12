var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
{
    // Do not use AllowAnyOrigin() here: the SPA origin is listed explicitly.
    options.AddPolicy("Spa", policy =>
        policy.WithOrigins("https://app.example.com")
              .AllowAnyHeader()
              .AllowAnyMethod());
});
var app = builder.Build();
app.UseCors("Spa");
app.Run();
