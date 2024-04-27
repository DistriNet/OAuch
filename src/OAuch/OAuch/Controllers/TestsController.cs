using Microsoft.AspNetCore.Mvc;
using OAuch.Compliance;
using OAuch.Helpers;
using OAuch.ViewModels;
using System.Linq;

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
                Requirements = []
            };
            foreach (var document in ComplianceDatabase.AllDocuments) {
                var req = document.Countermeasures.FirstOrDefault(c => c.Test.TestId == id);
                req ??= document.DeprecatedFeatures.FirstOrDefault(c => c.Test.TestId == id);
                if (req != null)
                    model.Requirements[document] = req;
            }
            return View(model);
        }
    }
}
