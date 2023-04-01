using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OAuch.ViewModels;

namespace OAuch.Controllers {
    public class HomeController : BaseController {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger) {
            _logger = logger;
        }

        public async Task<IActionResult> Index() {
            var claimType = "https://oauch.io/internalid";
            if (!this.User.Claims.Any(c => c.Type == claimType)) { // no active session
                // sign the user in as a dummy user
                var oauchIdentity = new ClaimsIdentity(new Claim[] {                
                    new Claim(claimType, this.OAuchInternalId!.Value.ToString("N"))
                    }, "OAuchAuthentication");
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(oauchIdentity), new AuthenticationProperties
                {
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