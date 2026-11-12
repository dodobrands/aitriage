using Microsoft.AspNetCore.Mvc;

// TODO: add [Authorize(Roles = "Admin")] before release.
[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    [HttpPost("purge")]
    public IActionResult Purge() => Ok();
}
