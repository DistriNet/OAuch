using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System.Collections.Generic;
using System.Linq;

namespace OAuch.Compliance.Results {
    public class DocumentComplianceReport : ComplianceReport {
        public DocumentComplianceReport(OAuthDocument document, IList<TestResult> results) : base(results, document.DeprecatedFeatures.Select(c => new DocumentTestRequirementLevel(document, c)), document.Countermeasures.Select(c => new DocumentTestRequirementLevel(document, c))) {
            this.Document = document;
            var supp = results.FirstOrDefault(r => r.TestId == document.IsSupportedTest);
            if (supp != null && (supp.Outcome == TestOutcomes.SpecificationFullyImplemented || supp.Outcome == TestOutcomes.SpecificationPartiallyImplemented))
                this.IsDocumentSupported = true;
            else
                this.IsDocumentSupported = false;
        }

        public OAuthDocument Document { get; }
        public bool IsDocumentSupported { get; }
    }
}
