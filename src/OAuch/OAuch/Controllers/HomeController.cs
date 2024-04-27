using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuch.Controllers {
    public class HomeController : BaseController {
        public HomeController() { }

        public async Task<IActionResult> Index() {
            var claimType = "https://oauch.io/internalid";
            if (!this.User.Claims.Any(c => c.Type == claimType)) { // no active session
                // sign the user in as a dummy user
                var oauchIdentity = new ClaimsIdentity([
                    new Claim(claimType, this.OAuchInternalId!.Value.ToString("N"))
                    ], "OAuchAuthentication");
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(oauchIdentity), new AuthenticationProperties {
                    IsPersistent = true
                });
            }
            return RedirectToAction("Index", "Dashboard");
        }
        public IActionResult Faq() {
            return View();
        }
        public IActionResult About() {
            return View();
        }
    }
}