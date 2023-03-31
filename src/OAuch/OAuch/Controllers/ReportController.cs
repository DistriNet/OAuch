using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.Extensions.Configuration;
using OAuch.Compliance;
using OAuch.Compliance.Results;
using OAuch.Compliance.Tests;
using OAuch.Database;
using OAuch.Database.Entities;
using OAuch.Helpers;
using OAuch.Shared.Settings;
using OAuch.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Controllers {
    [Authorize]
    public class ReportController : BaseController {
        public ReportController(OAuchDbContext db) {
            this.Database = db;
        }
        private OAuchDbContext Database { get; }

        public IActionResult Generate(Guid id /* resultid */, bool includeLog = false, bool includeSettings = false, bool allTests = false) {
            var serializedTestRun = Database.SerializedTestRuns.Where(str => str.TestResultId == id).SingleOrDefault();
            if (serializedTestRun == null)
                return NotFound();
            var site = Database.Sites.Where(st => st.SiteId == serializedTestRun.SiteId).SingleOrDefault();
            if (site == null || site.OwnerId != this.OAuchInternalId!.Value)
                return NotFound();

            var model = new ReportingViewModel {    
                IncludeLog = includeLog,
                IncludeSettings = includeSettings,
                IncludeSucceededTests = allTests,
                SiteId = site.SiteId,
                ResultId = id,
                SiteName = site.Name,
                StartedAt = serializedTestRun.StartedAt,
                Result = GetSiteResults(serializedTestRun),
            };
            return View(model);
        }
        [NonAction]
        private ComplianceResult GetSiteResults(SerializedTestRun serializedTestRun) {
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(serializedTestRun.ConfigurationJson);
            var docIds = OAuchJsonConvert.Deserialize<List<string>>(serializedTestRun.SelectedDocumentIdsJson);
            var documents = docIds.Select(did => ComplianceDatabase.AllDocuments.FirstOrDefault(d => d.Id == did)).Where(c => c != null).Select(c => c!);
            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            return new ComplianceResult(serializedTestRun.StartedAt, settings, documents, testResults);
        }
    }
}