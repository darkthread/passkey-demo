using Microsoft.AspNetCore.Mvc;

namespace passkey_demo.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Register()
        {
            return View();
        }

        public IActionResult Login()
        {
            return View();
        }

        public IActionResult Logout() {
            HttpContext.Session.Remove("UserId");
            return RedirectToAction("Index");
        }
    }
}
