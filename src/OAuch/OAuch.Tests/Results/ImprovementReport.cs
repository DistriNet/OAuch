using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Results {
    public class ImprovementReport {
        public ImprovementReport(Dictionary<string, TestResult> allResults, IList<ThreatReport> threatReports) {
            _improvements = new Dictionary<string, MitigationImprovement>();
            var threatInstances = threatReports.SelectMany(tr => tr.InstanceReports).Where(ir => ir.IsRelevant == true && ir.Outcome == TestOutcomes.SpecificationNotImplemented || ir.Outcome == TestOutcomes.SpecificationPartiallyImplemented).Select(tr => tr.ThreatInstance);
            foreach (var threatInstance in threatInstances) {
                var mitigatesThreat = new Dictionary<string, float>();
                foreach (var combination in threatInstance.MitigatedBy) {
                    ProcessTestCombination(combination, mitigatesThreat);
                }
                // update improvement stats for the found mitigations
                ProcessResults(mitigatesThreat);
            }
            // normalize scores
            if (_improvements.Count > 0) {
                var max = _improvements.Values.Max(v => v.Score);
                foreach (var v in _improvements.Values) {
                    v.Score /= max;
                }
            }


            void ProcessResults(Dictionary<string, float> mitigationResults) {
                foreach (var key in mitigationResults.Keys) {
                    var mi = this[key];
                    var score = mitigationResults[key];
                    if (score == 1f)
                        mi.FullyMitigatesCount++;
                    else
                        mi.PartiallyMitigatesCount++;
                    mi.Score += score;
                }
            }
            void ProcessTestCombination(TestCombination combination, Dictionary<string, float> mitigatesThreat) {
                //var trimmed = combination.Where(c => IsNotFullyImplemented(allResults[c.TestId].Outcome)).ToList();
                foreach(var v in combination) {
                    var score = 1 / (float)combination.Count;
                    if (!mitigatesThreat.TryGetValue(v.TestId, out var stored) || score > stored) {
                        mitigatesThreat[v.TestId] = score;
                    }
                }
            }
            //bool IsNotFullyImplemented(TestOutcomes? o) {
            //    return o == TestOutcomes.SpecificationNotImplemented || o == TestOutcomes.SpecificationPartiallyImplemented;
            //}
        }

        public MitigationImprovement this[string? testId] {
            get {
                testId ??= "";
                if (_improvements.TryGetValue(testId, out var value))
                    return value;
                var newMi = new MitigationImprovement(testId);
                _improvements[testId] = newMi;
                return newMi;
            }
        }

        private Dictionary<string, MitigationImprovement> _improvements;
    }
    public class MitigationImprovement { 
        public MitigationImprovement(string id) {
            this.TestId = id;
        }
        public string TestId { get; set; }
        public int FullyMitigatesCount { get; set; }
        public int PartiallyMitigatesCount { get; set; }
        public float Score { get; set; }
    }
}
