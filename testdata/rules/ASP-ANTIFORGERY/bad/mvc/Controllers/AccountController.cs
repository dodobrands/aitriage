using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    [HttpPost]
    public IActionResult ChangeEmail(string email) => RedirectToAction("Index");
}
