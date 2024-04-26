using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Results {
    public class InstanceReport { 
        public required ThreatInstance ThreatInstance { get; init; }
        public TestOutcomes? Outcome { get; init; }
        public bool? IsRelevant { get; init; }
    }
    public class ThreatReport {
        public ThreatReport(Threat threat, IList<TestResult> results) {
            this.Threat = threat;
            this.InstanceReports = threat.Instances.Select(i => new InstanceReport {
                ThreatInstance = i,
                IsRelevant = IsInstanceRelevant(results, i),
                Outcome = CalculateThreatInstanceOutcome(results, i.MitigatedBy)
            }).ToList();
            this.Outcome = CalculateThreatOutcome();
        }
        public Threat Threat { get; }
        /// <summary>
        /// <b>false</b> means that the vulnerability is not relevant, because the features it abuses are not enabled or present.
        /// </summary>
        public TestOutcomes? Outcome { get; }
        public List<InstanceReport> InstanceReports { get; }

        /// <summary>
        /// Check if all threat instances are mitigated
        /// </summary>
        private TestOutcomes? CalculateThreatOutcome() {
            int potentialRelevants = 0, skipped = 0;
            TestOutcomes? ret = TestOutcomes.SpecificationFullyImplemented;
            foreach (var instanceReport in InstanceReports) {
                if (instanceReport.IsRelevant != false) { // if relevant == null, consider the threat as potentially relevant (but actually we don't know yet)
                    if (instanceReport.Outcome == null)
                        return null; // we have a threat instance that is (potentially) relevant, but for which we do not have a result yet                    
                    switch (instanceReport.Outcome) {
                        case TestOutcomes.SpecificationPartiallyImplemented:
                            if (ret != TestOutcomes.Failed)
                                ret = TestOutcomes.SpecificationPartiallyImplemented;
                            break;
                        case TestOutcomes.SpecificationNotImplemented:
                            // we have a threat instance that is not implemented
                            return TestOutcomes.SpecificationNotImplemented;
                        case TestOutcomes.Failed:
                            // we have a threat instance that is (potentially) relevant, but for which we a test failed
                            // report this, unless another threat instance has not been implemented
                            ret = TestOutcomes.Failed;
                            break;
                        case TestOutcomes.Skipped:
                            skipped++;
                            break;
                        //case TestOutcomes.SpecificationFullyImplemented: // this is the default case
                    }
                    potentialRelevants++; // increase the number of threat instances that are (potentially) relevant
                } 
            }
            if (potentialRelevants > 0) // check if this threat is relevant
                return skipped == potentialRelevants ? null : ret;  // return null if all threat instances were skipped; in this case we have relevant threats, but no tests to confirm whether anything is implemented
            else
                return TestOutcomes.Skipped; // this threat is not relevant
        }

        /// <summary>
        /// <b>true</b> if the threat instance is considered to be relevant for the test set, <b>false</b> otherwise.
        /// If the test set contains tests that haven't been executed yet or that have failed, the result is <b>null</b>.
        /// </summary>
        private bool? IsInstanceRelevant(IEnumerable<TestResult> results, ThreatInstance instance) {
            bool? ret = false;
            foreach (var feat in instance.DependsOnFeatures) {
                var result = results.Where(r => r.TestId == feat.TestId).FirstOrDefault();
                if (result != null) {
                    if (result.Outcome == TestOutcomes.SpecificationFullyImplemented || result.Outcome == TestOutcomes.SpecificationPartiallyImplemented)
                        return true;
                    else if (result.Outcome == null || result.Outcome == TestOutcomes.Failed)
                        ret = null; // the test set is not complete, or at least one test failed
                } // else: the feature has not been tested, so skip it
            }
            return ret;
        }

        /// <summary>
        /// Check if there is any TestCombination that mitigates the threat instance
        /// </summary>
        private TestOutcomes? CalculateThreatInstanceOutcome(IEnumerable<TestResult> results, List<TestCombination> mitigations) {
            if (mitigations.Count == 0) // there are no mitigations for this threat; if it is relevant (i.e., if the preconditions are met, the implementation is vulnerable)
                return TestOutcomes.SpecificationNotImplemented;

            TestOutcomes? ret = TestOutcomes.SpecificationNotImplemented;
            int skipped = 0;
            foreach (var mitigation in mitigations) {
                var mo = CalculateCombinationOutcome(mitigation, results);
                if (mo == null) {
                    ret = null; // there are tests that have not been run yet, so we don't know the final answer (unless it is fully mitigated by another countermeasure)
                } else {
                    switch (mo) {
                        case TestOutcomes.SpecificationFullyImplemented:
                            return TestOutcomes.SpecificationFullyImplemented;
                        case TestOutcomes.SpecificationPartiallyImplemented:
                            if (ret != TestOutcomes.Failed) // if one test has failed, report this failed test because it could potentially fully mitigate the vulnerability
                                ret = TestOutcomes.SpecificationPartiallyImplemented;
                            break;
                        case TestOutcomes.Failed:
                            ret = TestOutcomes.Failed;
                            break;
                        //case TestOutcomes.CountermeasureNotImplemented: // this is the default value
                        //case TestOutcomes.Skipped: // ignore skipped tests
                        case TestOutcomes.Skipped:
                            skipped++;
                            break;
                    }
                }
            }
            if (skipped == mitigations.Count)
                return TestOutcomes.Skipped;
            return ret;
        }
        /// <summary>
        /// Check if every test in the TestCombination succeeds
        /// </summary>
        public TestOutcomes? CalculateCombinationOutcome(TestCombination combination, IEnumerable<TestResult> results) {
            int partials = 0, full = 0, not = 0, skipped = 0;
            foreach (var test in combination) {
                var result = results.Where(r => r.TestId == test.TestId).FirstOrDefault();
                if (result == null || result.Outcome == null)
                    return null; // we're missing a test to calculate the result
                switch (result.Outcome) {
                    case TestOutcomes.SpecificationFullyImplemented:
                        full++;
                        break;
                    case TestOutcomes.SpecificationPartiallyImplemented:
                        partials++;
                        break;
                    case TestOutcomes.Failed:
                        return TestOutcomes.Failed;
                    case TestOutcomes.SpecificationNotImplemented:
                        not++;
                        break;
                    case TestOutcomes.Skipped:
                        skipped++;
                        break;
                }
            }
            if (skipped == combination.Count)
                return TestOutcomes.Skipped; // all tests were skipped

            if (partials + full == 0) // if we do not have any (partially) succeeded test....
                return TestOutcomes.SpecificationNotImplemented;
            else if (partials > 0 || not > 0) // some countermeasures are partially implemented
                return TestOutcomes.SpecificationPartiallyImplemented;
            else // all countermeasures are fully implemented
                return TestOutcomes.SpecificationFullyImplemented;
        }
    }
}