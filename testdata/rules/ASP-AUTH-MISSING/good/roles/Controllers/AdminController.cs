using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController, Route("admin")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    [HttpPost("purge")]
    public IActionResult Purge() => Ok();
}
