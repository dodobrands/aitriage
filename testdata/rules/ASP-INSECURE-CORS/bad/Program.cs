var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
{
    options.AddPolicy("Open", policy =>
        // ruleid: ASP-INSECURE-CORS
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader());
});
var app = builder.Build();
app.UseCors("Open");
app.Run();
