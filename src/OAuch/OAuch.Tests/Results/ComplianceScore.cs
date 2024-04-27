using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;

namespace OAuch.Compliance.Results {
    public class ComplianceScore {
        public ComplianceScore(IEnumerable<TestResult> results) {
            this.SucceededTests = results.Count(t => t.Outcome == TestOutcomes.SpecificationFullyImplemented || t.Outcome == TestOutcomes.SpecificationPartiallyImplemented);
            this.FailedTests = results.Count(t => t.Outcome == TestOutcomes.SpecificationNotImplemented);
        }
        public int SucceededTests { get; }
        public int FailedTests { get; }
        public float SuccessRate => SucceededTests / (float)TotalTests;
        public float FailureRate => FailedTests / (float)TotalTests;
        public int TotalTests => SucceededTests + FailedTests;
    }
}
