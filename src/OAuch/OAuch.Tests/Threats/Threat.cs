using OAuch.Compliance.Tests;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace OAuch.Compliance.Threats {
    public abstract class Threat {
        public Threat() {
            DependsOnFeatures = new List<Test>();
            MitigatedBy = new List<TestCombination>();
        }
        private Test GetTest<T>() where T : Test {
            var t = typeof(T);
            Debug.Assert(t.FullName != null);
            var found = ComplianceDatabase.Tests.TryGetValue(t.FullName, out var result);
            Debug.Assert(found);
            return result!;
        }
        protected (Test Mitigation, float Contribution) Mit<T>(float contribution) where T : Test {
            var t = typeof(T);
            Debug.Assert(t.FullName != null);
            var found = ComplianceDatabase.Tests.TryGetValue(t.FullName, out var result);
            Debug.Assert(found);
            return (result!, contribution);
        }
        protected void AddDependency<T>() where T : Test => DependsOnFeatures.Add(GetTest<T>());
        protected void AddMitigation(params (Test, float)[] v) => MitigatedBy.Add(new TestCombination(v));

        public abstract string Id { get; }
        public abstract string Title { get; }
        public abstract string Description { get; }
        public abstract OAuthDocument Document { get; }
        public abstract string LocationInDocument { get; }
        public abstract string? ExtraDescription { get; }
        public List<Test> DependsOnFeatures { get; } // if any of these tests (partially) succeeds, the vulnerability is considered relevant
        public List<TestCombination> MitigatedBy { get; } // if any of these tests (partially) succeeds, the vulnerability is considered (partially) mitigated
        public virtual string? AliasOf => null; //used for BCP threats that are an alias of threats in RFC6819
        public abstract ExecutionDifficulties ExecutionDifficulty { get; } // how difficult is it for an attacker to set up an exploit for the threat (assuming the threat is not mitigated)

        // for backward compatibility
        public List<ThreatInstance> Instances => [new ThreatInstance { ExtraDescription = ExtraDescription, DependsOnFeatures = DependsOnFeatures, MitigatedBy = MitigatedBy }];
    }

    public class TestCombination : IEnumerable<Test> {
        public TestCombination(params (Test Test, float Contribution)[] tests) {
            _testsWithContributions = new Dictionary<Test, float>();
            foreach(var t in tests) {
                _testsWithContributions[t.Test] = t.Contribution;
            }
        }
        // this represents an AND-list of tests
        // ALL tests must (partially) succeed (or skipped - this means the test is irrelevant)
        // every test has an importance that contributes to the value that determines how well this list of tests is implemented

        public float? CalculateCompletenessScore(Dictionary<string, TestResult> testResults) { // value that represents how complete this testcombination has been implemented according to the given test results (value between [0..1], with 0 = not implemented, 1 = fully implemented)
            float max = 0, score = 0;
            foreach(var t in _testsWithContributions) {
                if (testResults.TryGetValue(t.Key.TestId, out var result)) {
                    if (result.Outcome == Shared.Enumerations.TestOutcomes.SpecificationFullyImplemented || result.Outcome == Shared.Enumerations.TestOutcomes.SpecificationPartiallyImplemented || result.Outcome == Shared.Enumerations.TestOutcomes.SpecificationNotImplemented) {
                        // we have tested the specification, so it contributes to the completeness score
                        max += t.Value;
                        score += result.ImplementationScore!.Value * t.Value;
                    }
                }
            }
            if (max == 0)
                return null;
            return score / max;
        }
        public float MaxImpact { 
            get {
                return _testsWithContributions.Sum(c => c.Value);
            }
        }
        public float? GetImpact(Test test) { 
            if (_testsWithContributions.TryGetValue(test, out var ret)) 
                return ret;
            return null;
        }

        private Dictionary<Test, float> _testsWithContributions;

        public IEnumerator<Test> GetEnumerator() => _testsWithContributions.Keys.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => _testsWithContributions.Keys.GetEnumerator();
        public int Count => _testsWithContributions.Count;
    }
    public class ThreatInstance {
        public string? ExtraDescription { get; init; }
        public required List<Test> DependsOnFeatures { get; init; } // if any of these tests (partially) succeeds, the vulnerability is considered relevant
        public required List<TestCombination> MitigatedBy { get; init; } // if any of these tests (partially) succeeds, the vulnerability is considered (partially) mitigated
    }
    public enum ExecutionDifficulties { 
        Easy, // can be initiated by attacker
        Reasonable, // requires access to some public system or requires lots of resources
        Hard // requires access to some private system or relies on redirecting network traffic
    }
}
