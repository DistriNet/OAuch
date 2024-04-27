using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using OAuch.Shared;
using OAuch.TestRuns;
using OAuch.ViewModels;
using System;
using System.Linq;

namespace OAuch.Controllers {
    public class CallbackController : BaseController {
        public IActionResult Index() {
            var form = "";
            try {
                if (this.Request.Form.Count > 0)
                    form = EncodingHelper.FormUrlEncodeAsString(this.Request.Form);
            } catch { /* not a post request */ }
            return View("~/Views/Callback/Index.cshtml", new CallbackViewModel(form));
        }
        public IActionResult Wrong() {
            return Index();
        }
        public IActionResult Caught() {
            // there might not be a current user, because the user might call this endpoint through a non-standard domain
            // in this case, the browser doesn't send the authentication cookie
            var requested = new Uri(this.Request.GetDisplayUrl());
            // verify that there is at least one active TestManager that expects this callback
            foreach (var manager in TestRunManager.Current) {
                var callbackUri = manager.Context.SiteSettings.CallbackUri;
                if (!string.IsNullOrWhiteSpace(callbackUri) && Uri.TryCreate(callbackUri, UriKind.Absolute, out var expectedUri)) {
                    // only compare the host; other details are less relevant
                    if (Uri.Compare(requested, expectedUri, UriComponents.NormalizedHost, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0)
                        return Index();
                }
            }
            return NotFound();
        }
        public IActionResult Orphaned(string href, string form) {
            // this action is called if the OAuth implementation closed our parent (monitoring) window
            // solve this by finding a running test manager for this user that expects a callback, and
            // then redirecting the user to a new monitoring page of that test manager
            var currentUser = this.OAuchInternalId;
            if (currentUser == null)
                return View(); // sorry, we can't fix it

            var results = TestRunManager.Current.Where(c => c.OwnerId == currentUser).ToList();
            if (results.Count == 0)
                return View(); // sorry, we can't fix it

            var result = results.FirstOrDefault(r => r.Browser.CurrentCallback != null);
            if (result == null) {
                result = results.First();
            } else {
                result.OnCallback(href, form); // process callback
            }
            return RedirectToAction("Running", "Dashboard", new { id = result.SiteId });
        }
        public IActionResult Initial() {
            return View();
        }
        public IActionResult Skipped() {
            return View();
        }
        public IActionResult PostRedirect(Guid id /* manager Id */, string values) {
            // make sure it doesn't become an open redirector
            var manager = TestRunManager.ManagerById(id);
            if (manager != null) {
                var data = EncodingHelper.EncodedFormToDictionary(EncodingHelper.Base64UrlDecodeAsString(values));

                // check callback uri
                //if (data.ContainsKey("redirect_uri") && data["redirect_uri"] == manager.Context.Site.Settings.CallbackUri) { 
                var authUri = new Uri(manager.Context.SiteSettings.AuthorizationUri ?? "");
                return View(new PostRedirectViewModel() {
                    PostUrl = authUri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.SafeUnescaped),
                    FormValues = data
                });
                //}
            }
            return NotFound();
        }
    }
}
