using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("import")]
public class ImportController : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Import()
    {
        using var reader = new StreamReader(Request.Body);
        var body = await reader.ReadToEndAsync();
        var templates = System.IO.File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "queryTemplates.json"));
        return Ok(body.Length + templates.Length);
    }
}
