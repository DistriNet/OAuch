using Microsoft.AspNetCore.Mvc;
using OAuch.Compliance;
using OAuch.ViewModels;
using System.Linq;

namespace OAuch.Controllers {
    public class ThreatsController : Controller {
        public IActionResult Index() {
            return View(new ThreatsViewModel { Threats = ComplianceDatabase.AllThreats });
        }
        public IActionResult Info(string id) {
            var threat = ComplianceDatabase.AllThreats.FirstOrDefault(t => t.Id == id);
            if (threat == null)
                return NotFound();
            return View(new ThreatViewModel(threat));
        }
    }
}
