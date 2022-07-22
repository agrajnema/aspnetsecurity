using AuthenticationAuthorization.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthenticationAuthorization.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Secured()
        {
            var token = await HttpContext.GetTokenAsync("id_token");
            return View();
        }
        public IActionResult Privacy()
        {
            return View();
        }
        [HttpGet("login")]
        public IActionResult Login(string returnUrl)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpGet("login/{provider}")]
        public IActionResult LoginExternal([FromRoute]string provider, [FromQuery]string returnUrl)
        {
            if(User != null && User.Identities.Any(i => i.IsAuthenticated))
            {
                RedirectToAction("", "Home");
            }
            returnUrl = String.IsNullOrEmpty(returnUrl) ? "/" : returnUrl;
            var authenticationProperties = new AuthenticationProperties { RedirectUri = returnUrl };
            return new ChallengeResult(provider, authenticationProperties);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Validate(string userName, string password, string returnUrl)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if(userName == "agraj" && password == "nema")
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, "Agraj"),
                    new Claim(ClaimTypes.NameIdentifier, userName),
                    new Claim("username", userName),
                };
                var claimsIdentity = new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme);
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                var items = new Dictionary<string, string>();
                items.Add(".AuthScheme",  CookieAuthenticationDefaults.AuthenticationScheme);
                var authenticationProperties = new AuthenticationProperties(items);
                await HttpContext.SignInAsync(claimsPrincipal,authenticationProperties);
                return Redirect(returnUrl);
            }
            TempData["Error"] = "Error. Please enter valid credentials to login";
            return View("login");
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var scheme = User.Claims.FirstOrDefault(c => c.Type == ".AuthScheme").Value;
            if (scheme == "google")
            {
                await HttpContext.SignOutAsync();
                return Redirect("https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ah/logout?continue=https://localhost:5001");
            }
            else
            {
                return new SignOutResult(new[] {CookieAuthenticationDefaults.AuthenticationScheme, scheme});
            }
        }

        [HttpGet("accessDenied")]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
