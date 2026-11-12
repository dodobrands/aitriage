using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("orders")]
public class OrdersController : ControllerBase
{
    [HttpDelete("{id}")]
    public IActionResult Delete(int id) => NoContent();
}
