using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System.Collections.Generic;
using System.Linq;

namespace OAuch.Compliance.Results {
    public class SpecificationCompliance {
        public SpecificationCompliance(DocumentTestRequirementLevel dtrl, IList<TestResult> results, bool isDeprecatedFeature = false) {
            _isDeprecatedFeature = isDeprecatedFeature;
            _docReqLevel = dtrl;
            this.TestResult = results.FirstOrDefault(r => r.TestId == dtrl.TestRequirementLevel.Test.TestId);
        }
        public RequirementLevels RequirementLevel => _docReqLevel.TestRequirementLevel.RequirementLevel;
        public string SpecificationLocationInDocument => _docReqLevel.TestRequirementLevel.LocationInDocument;
        public TestOutcomes? Outcome => this.TestResult?.Outcome;
        public OAuthDocument Document => _docReqLevel.Document;
        public bool? IsCompliant {
            get {
                var oc = Outcome;
                if (oc == null || oc == TestOutcomes.Failed)
                    return null;
                if (oc == TestOutcomes.Skipped)
                    return true;
                return oc == TestOutcomes.SpecificationNotImplemented ? _isDeprecatedFeature : !_isDeprecatedFeature;
            }
        }
        public TestResult? TestResult { get; }

        private readonly bool _isDeprecatedFeature;
        private readonly DocumentTestRequirementLevel _docReqLevel;
    }
}
