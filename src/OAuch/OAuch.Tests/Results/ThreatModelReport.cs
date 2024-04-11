using OAuch.Compliance.Tests;
using OAuch.OAuthThreatModel;
using OAuch.OAuthThreatModel.Consequences;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Results {
    public class ThreatModelReport {
        public ThreatModelReport(IList<TestResult> allResults, IList<ThreatReport> threatReports) {
            var context = new ThreatModelContext(allResults, threatReports);
            
            // simple algo





        }


        private class ThreatModelContext : IThreatModelContext {
            public ThreatModelContext(IList<TestResult> allResults, IList<ThreatReport> threatReports) {
                this.CurrentState = new List<ConsequenceType>();
                // cache the testcase implementation results
                testcaseImplemented = new Dictionary<string, bool>();
                foreach (var tc in allResults) {
                    if (tc.Outcome != null) {
                        switch (tc.Outcome) {
                            case TestOutcomes.SpecificationFullyImplemented:
                            case TestOutcomes.SpecificationPartiallyImplemented:
                                testcaseImplemented[tc.TestId] = true;
                                break;
                            case TestOutcomes.SpecificationNotImplemented:
                                testcaseImplemented[tc.TestId] = false;
                                break;
                        }
                    }
                }

                // cache the threat results
                threatUnmitigated = new Dictionary<string, bool>();
                foreach (var tr in threatReports) {
                    if (tr.Outcome != null) {
                        switch (tr.Outcome) {
                            case TestOutcomes.SpecificationNotImplemented:
                                threatUnmitigated[tr.Threat.Id] = true;
                                break;
                            case TestOutcomes.SpecificationFullyImplemented:
                            case TestOutcomes.SpecificationPartiallyImplemented:
                                threatUnmitigated[tr.Threat.Id] = false;
                                break;
                        }
                    }
                }
            }

            private Dictionary<string, bool> testcaseImplemented;
            private Dictionary<string, bool> threatUnmitigated;

            public IList<ConsequenceType> CurrentState { get; }

            public bool? IsTestcaseImplemented(string id) {
                if (testcaseImplemented.TryGetValue(id, out var value))
                    return value;
                return null;
            }

            public bool? IsThreatUnmitigated(string id) {
                if (threatUnmitigated.TryGetValue(id, out var value))
                    return value;
                return null;
            }
        }
    }
}
