using Microsoft.AspNetCore.Mvc;
using OAuch.Compliance;
using OAuch.Helpers;
using OAuch.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Controllers {
    public class TestsController : BaseController {
        public IActionResult Index() {
            return View(new TestsViewModel() {
                Tests = ComplianceDatabase.AllTests
            });
        }
        public IActionResult Info(string id) {
            id = HelperMethods.LengthenTestId(id);
            if (!ComplianceDatabase.Tests.TryGetValue(id, out var test))
                return NotFound();
            var model = new TestViewModel() {
                Test = test,
                Requirements = new Dictionary<OAuthDocument, TestRequirementLevel>()
            };
            foreach(var document in ComplianceDatabase.AllDocuments) {
                var req = document.Countermeasures.Where(c => c.Test.TestId == id).FirstOrDefault();
                if (req == null)
                    req = document.DeprecatedFeatures.Where(c => c.Test.TestId == id).FirstOrDefault();
                if (req != null)
                    model.Requirements[document] = req;
            }
            return View(model);
        }
    }
}
