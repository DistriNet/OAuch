using OAuch.Compliance.Tests;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.OAuth2;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;

namespace OAuch.Compliance.Results {
    public class ComplianceResult {
        public ComplianceResult(DateTime startedAt, SiteSettings settings, IEnumerable<OAuthDocument> docs, IEnumerable<TestResult> testResults) {
            this.StartedAt = startedAt;
            this.TestSettings = settings;

            this.AllResults = [];
            if (testResults != null)
                this.AllResults.AddRange(testResults);
            _allResults = this.AllResults.ToDictionary(i => i.TestId);

            this.SkippedTests = this.AllResults.Count(c => c.Outcome == TestOutcomes.Skipped);
            this.FailedTests = this.AllResults.Count(c => c.Outcome == TestOutcomes.Failed);
            this.PendingTests = this.AllResults.Count(c => c.Outcome == null);
            if (this.PendingTests > 0) {
                foreach (var pt in this.AllResults.Where(t => t.Outcome == null)) {
                    if (pt is not IHasInfo cr) {
                        // the test has not been executed yet
                        this.ResumeWhen = DateTime.Now;
                        break;
                    } else {
                        var ei = cr.ExtraInfo as ITimeDelayedTest;
                        if (ei?.ResumeWhen != null) {
                            if (this.ResumeWhen == null) {
                                this.ResumeWhen = ei.ResumeWhen;
                            } else if (ei.ResumeWhen < this.ResumeWhen) {
                                this.ResumeWhen = ei.ResumeWhen;
                            }
                        }
                    }
                }
            }

            this.ExecutedTests = new ComplianceScore(this.AllResults);

            this.DocumentCompliance = docs.Select(d => new DocumentComplianceReport(d, this.AllResults)).ToList();
            this.StandardsCompliance = CalculateCompliance(d => d.Document.IsStandard);
            this.OverallCompliance = CalculateCompliance(d => true);

            this.ThreatReports = ComplianceDatabase.AllThreats.Select(v => new ThreatReport(v, this.AllResults)).ToList();
            this.FullyMitigatedThreats = this.ThreatReports.Count(tr => tr.Outcome == TestOutcomes.SpecificationFullyImplemented);
            this.PartiallyMitigatedThreats = this.ThreatReports.Count(tr => tr.Outcome == TestOutcomes.SpecificationPartiallyImplemented);
            this.UnmitigatedThreats = this.ThreatReports.Count(tr => tr.Outcome == TestOutcomes.SpecificationNotImplemented);
        }

        //private IEnumerable<Threat> GetRelevantThreats(IList<TestResult> results) {
        //    var ret = new List<Threat>();
        //    foreach (var threat in ComplianceDatabase.AllThreats) {
        //        foreach(var tinst in threat.Instances) {
        //            foreach (var feat in tinst.DependsOnFeatures) {
        //                if (results.Any(c => c.TestId == feat.TestId)) {
        //                    ret.Add(threat);
        //                    break;
        //                }
        //            }
        //        }
        //    }
        //    return ret;
        //}
        private ComplianceReport CalculateCompliance(Func<DocumentComplianceReport, bool> documentTest) {
            var deprecatedFeatures = new Dictionary<string, DocumentTestRequirementLevel>();
            var countermeasures = new Dictionary<string, DocumentTestRequirementLevel>();
            foreach (var doc in this.DocumentCompliance) {
                if (!doc.IsDocumentSupported || !documentTest(doc))
                    continue; // the document is not supported or filtered out; do not integrate the results into the overall compliance report

                foreach (var feat in doc.Document.DeprecatedFeatures) {
                    var found = deprecatedFeatures.TryGetValue(feat.Test.TestId, out var trl);
                    if (!found || MustReplace(trl!.TestRequirementLevel.RequirementLevel, feat.RequirementLevel)) {
                        deprecatedFeatures[feat.Test.TestId] = new DocumentTestRequirementLevel(doc.Document, feat);
                    }
                }
                foreach (var count in doc.Document.Countermeasures) {
                    var found = countermeasures.TryGetValue(count.Test.TestId, out var trl);
                    if (!found || MustReplace(trl!.TestRequirementLevel.RequirementLevel, count.RequirementLevel)) {
                        countermeasures[count.Test.TestId] = new DocumentTestRequirementLevel(doc.Document, count);
                    }
                }
            }
            return new ComplianceReport(this.AllResults, deprecatedFeatures.Values, countermeasures.Values);

            static bool MustReplace(RequirementLevels storedRl, RequirementLevels newRl) {
                if (storedRl == newRl
                        || storedRl == RequirementLevels.Must
                        || (storedRl == RequirementLevels.Should && newRl != RequirementLevels.Must)
                        || newRl == RequirementLevels.May)
                    return false;
                return true;
            }
        }
        public DateTime StartedAt { get; }


        public int SkippedTests { get; }
        public int FailedTests { get; }
        public int PendingTests { get; }
        public DateTime? ResumeWhen { get; }
        public ComplianceScore ExecutedTests { get; }
        public int FullyMitigatedThreats { get; }
        public int PartiallyMitigatedThreats { get; }
        public int UnmitigatedThreats { get; }
        public SiteSettings TestSettings { get; }
        public SimpleRatings SimpleRating {
            get {
                if (this.UnmitigatedThreats == 0) {
                    return SimpleRatings.APlus;
                } else if (UnmitigatedThreats == 1) {
                    return SimpleRatings.A;
                } else if (UnmitigatedThreats <= 5) {
                    return SimpleRatings.B;
                }
                return SimpleRatings.C;
            }
        }

        public IReadOnlyList<TokenProviderInfo> SupportedFlows {
            get {
                if (_supportedFlows == null) {
                    _supportedFlows = [];
                    foreach (var result in AllResults) {
                        var flowResult = result as FlowSupportedTestResult;
                        if (flowResult?.ExtraInfo?.Settings != null) {
                            _supportedFlows.Add(flowResult.ExtraInfo);
                        }
                    }
                }
                return _supportedFlows;
            }
        }
        private List<TokenProviderInfo>? _supportedFlows;

        public ComplianceReport OverallCompliance { get; }
        public ComplianceReport StandardsCompliance { get; }
        public IList<DocumentComplianceReport> DocumentCompliance { get; }
        public IList<ThreatReport> ThreatReports { get; }

        public ImprovementReport ImprovementReport {
            get {
                _improvementReport ??= new ImprovementReport(/*_allResults,*/ this.ThreatReports);
                return _improvementReport;
            }
        }
        private ImprovementReport? _improvementReport;

        public AttackReport GetAttackReport(IEnumerable<string> selectedElements, ThreatModelContext? existingContext = null) {
            return new AttackReport(this.AllResults, this.ThreatReports, selectedElements, existingContext);
        }

        public List<TestResult> AllResults { get; }
        public TestResult? this[string testId] {
            get {
                if (_allResults.TryGetValue(testId, out var val)) {
                    return val;
                }
                return null;
            }
        }
        private readonly Dictionary<string, TestResult> _allResults;
    }

    public enum SimpleRatings {
        APlus,
        A,
        B,
        C
    }
}