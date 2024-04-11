using OAuch.Compliance.Tests;
using OAuch.OAuthThreatModel;
using OAuch.OAuthThreatModel.Consequences;
using OAuch.OAuthThreatModel.Enrichers;
using OAuch.OAuthThreatModel.Flows;
using OAuch.OAuthThreatModel.Threats;
using OAuch.Shared.Enumerations;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Results {
    public class ThreatModelReport {
        public ThreatModelReport(IList<TestResult> allResults, IList<ThreatReport> threatReports) {
            this.UnmitigatedVulnerabilities = new LinkedList<ThreatChain>();
            var state = new TMStateCollection();
            var context = new ThreatModelContext(allResults, threatReports, state);
            var start = DateTime.Now;
            CalculateModelDependencies(context, state);
            var stop = DateTime.Now.Subtract(start);
        }

        private void CalculateModelDependencies(ThreatModelContext context, TMStateCollection state) {
            var modelElements = new List<ModelElement>();
            modelElements.AddRange(Enricher.All.Where(c => c.IsRelevant(context))); // add all relevant enrichers
            modelElements.AddRange(OAuthThreatModel.Threats.Threat.All.Where(c => c.IsRelevant(context))); // add all not-fully mitigated countermeasures
            foreach (var flow in Flow.All.Where(c => c.IsRelevant(context))) {
                var ll = new LinkedList<ModelElement>();
                ll.AddFirst(flow);
                state.PushConsequences(flow.Consequences);
                BuildChain(context, state, ll, modelElements);
                state.PopConsequences();
            }
        }
        private void BuildChain(ThreatModelContext context, TMStateCollection state, LinkedList<ModelElement> currentChain, IList<ModelElement> availableElements) { 
            for(int i = 0; i < availableElements.Count; i++) {
                var el = availableElements[i];
                if (el.ArePreconditionsMet(context)) {
                    // try this item
                    availableElements.RemoveAt(i);
                    currentChain.AddLast(el);
                    state.PushConsequences(el.Consequences);
                    // check for vuln.; if not found, recurse
                    if (el.Consequences.Any(c => c.IsVulnerability)) { // if the added modelelement introduces a vulnerability, ...
                        ReportChain(context, currentChain, state);
                    } else { // if not, continue recursively
                        BuildChain(context, state, currentChain, availableElements);
                    }
                    // restore item
                    state.PopConsequences();
                    currentChain.RemoveLast();
                    availableElements.Insert(i, el);
                }
            }
        }

        private void ReportChain(ThreatModelContext context, LinkedList<ModelElement> currentChain, TMStateCollection state) {
            // make sure we don't have the same (or a better) chain already
            var node = this.UnmitigatedVulnerabilities.First;
            while (node != null) { // loop through the existing nodes
                var elementsInChainNotInCurrent = node.Value.ChainElements.Count(c => !currentChain.Contains(c));
                var elementsInCurrentNotInChain= currentChain.Count(c => !node.Value.ChainElements.Contains(c));

                var next = node.Next;
                if (elementsInCurrentNotInChain > 0 && elementsInChainNotInCurrent == 0) { // currentChain is a superset of an existing chain
                    return; // the chain we already have is better
                } else if (elementsInChainNotInCurrent > 0 && elementsInCurrentNotInChain == 0) { // currentchain is a subset of an existing chain
                    this.UnmitigatedVulnerabilities.Remove(node); // remove the one we already have because it's worse
                } else if (elementsInCurrentNotInChain == 0 && elementsInChainNotInCurrent == 0) {  // currentchain is the same as existing chain
                    return; // we already have the same chain
                }
                node = next;
            }

            // add the chain
            var tc = new ThreatChain(currentChain.ToList(), state.Where(c => c.IsVulnerability).ToList());
            this.UnmitigatedVulnerabilities.AddLast(tc);
        }

        public LinkedList<ThreatChain> UnmitigatedVulnerabilities { get; }


        public class ThreatChain {
            public ThreatChain(IReadOnlyList<ModelElement> elements, IReadOnlyList<ConsequenceType> consequences) {
                this.ChainElements = elements;
                this.Consequences = consequences;
            }
            public IReadOnlyList<ModelElement> ChainElements { get; }
            public IReadOnlyList<ConsequenceType> Consequences { get; }

            public override string ToString() {
                var sb = new StringBuilder();
                for(int i = 0; i < ChainElements.Count; i++) {
                    sb.Append(ChainElements[i].GetType().Name);
                    if (i != ChainElements.Count -1) {
                        sb.Append(" => ");
                    }
                }
                return sb.ToString();
            }
        }

        private class TMStateCollection : IEnumerable<ConsequenceType> {
            public TMStateCollection() => _state = new LinkedList<IReadOnlyList<ConsequenceType>>();
            public void PushConsequences(IReadOnlyList<ConsequenceType> consequences) => _state.AddLast(consequences);
            public void PopConsequences() => _state.RemoveLast();
            IEnumerator IEnumerable.GetEnumerator() => this.GetEnumerator();
            public IEnumerator<ConsequenceType> GetEnumerator() {
                foreach (var se in _state) {
                    foreach (var ct in se) {
                        yield return ct;
                    }
                }
            }
            public void Clear() {
                _state.Clear();
            }
            private LinkedList<IReadOnlyList<ConsequenceType>> _state;
        }

        private class ThreatModelContext : IThreatModelContext {
            public ThreatModelContext(IList<TestResult> allResults, IList<ThreatReport> threatReports, IEnumerable<ConsequenceType> state) {
                this.CurrentState = state;
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
                threatNotMitigated = new Dictionary<string, bool>();
                foreach (var tr in threatReports) {
                    if (tr.Outcome != null) {
                        switch (tr.Outcome) {
                            case TestOutcomes.SpecificationNotImplemented:
                                threatNotMitigated[tr.Threat.Id] = true;
                                break;
                            case TestOutcomes.SpecificationPartiallyImplemented:
                            case TestOutcomes.SpecificationFullyImplemented:
                                threatNotMitigated[tr.Threat.Id] = false;
                                break;
                        }
                    }
                }
                this.ThreatReports = threatReports.ToDictionary(c => c.Threat.Id);
            }

            private Dictionary<string, bool> testcaseImplemented;
            private Dictionary<string, bool> threatNotMitigated;

            public IEnumerable<ConsequenceType> CurrentState { get; }
            public IDictionary<string, ThreatReport> ThreatReports { get; }

            public bool? IsTestcaseImplemented(string id) {
                if (testcaseImplemented.TryGetValue(id, out var value))
                    return value;
                return null;
            }

            public bool? IsThreatNotMitigated(string id) {
                if (threatNotMitigated.TryGetValue(id, out var value))
                    return value;
                return null;
            }
        }
    }
}
