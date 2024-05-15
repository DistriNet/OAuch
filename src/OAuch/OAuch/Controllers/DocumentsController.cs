using Microsoft.AspNetCore.Mvc;
using OAuch.Compliance;
using OAuch.ViewModels;
using System.Linq;

namespace OAuch.Controllers {
    public class DocumentsController : Controller {
        public IActionResult Index() {
            return View(new DocumentsViewModel { Documents = ComplianceDatabase.AllDocuments });
        }
        public IActionResult Info(string id) {
            var document = ComplianceDatabase.AllDocuments.FirstOrDefault(t => t.Id == id);
            if (document == null)
                return NotFound();
            return View(new DocumentViewModel(document));
        }
    }
}
