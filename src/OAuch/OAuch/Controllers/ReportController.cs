using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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
using System.IO;
using System.Linq;

namespace OAuch.Controllers {
    [Authorize]
    public class ReportController : BaseController {
        public ReportController(OAuchDbContext db) {
            this.Database = db;
        }
        private OAuchDbContext Database { get; }

        public IActionResult Generate(Guid id /* resultid */, bool includeLog = false, bool includeSettings = false, bool includeIndividualTests = false, bool allTests = false, bool includeDeprecated = false, bool includeThreats = false) {
            var serializedTestRun = Database.SerializedTestRuns.Where(str => str.TestResultId == id).SingleOrDefault();
            if (serializedTestRun == null)
                return NotFound();
            var site = Database.Sites.Where(st => st.SiteId == serializedTestRun.SiteId).SingleOrDefault();
            if (site == null || site.OwnerId != this.OAuchInternalId!.Value)
                return NotFound();

            var model = new ReportingViewModel {
                IncludeLog = includeLog,
                IncludeSettings = includeSettings,
                IncludeIndividualTests = includeIndividualTests,
                IncludeSucceededTests = allTests,
                IncludeDeprecatedFeatures = includeDeprecated,
                IncludeThreats = includeThreats,
                SiteId = site.SiteId,
                ResultId = id,
                SiteName = site.Name,
                StartedAt = serializedTestRun.StartedAt,
                Result = GetSiteResults(serializedTestRun),
            };
            return View(model);
        }
        [NonAction]
        private static ComplianceResult GetSiteResults(SerializedTestRun serializedTestRun) {
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(serializedTestRun.ConfigurationJson);
            var docIds = OAuchJsonConvert.Deserialize<List<string>>(serializedTestRun.SelectedDocumentIdsJson);
            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            if (settings == null || docIds == null || testResults == null)
                throw new InvalidDataException("Could not deserialize the test run.");
            var documents = docIds.Select(did => ComplianceDatabase.AllDocuments.FirstOrDefault(d => d.Id == did)).Where(c => c != null).Select(c => c!);
            return new ComplianceResult(serializedTestRun.StartedAt, settings, documents, testResults);
        }
    }
}