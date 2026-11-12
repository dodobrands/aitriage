using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("files")]
public class FilesController : ControllerBase
{
    private readonly string _root = "/srv/files";

    [HttpGet("download")]
    public IActionResult Download()
    {
        // ruleid: ASP-PATH-TRAVERSAL
        var path = Path.Combine(_root, Request.Query["file"]);
        return PhysicalFile(path, "application/octet-stream");
    }
}
