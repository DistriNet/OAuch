using OAuch.Compliance.Tests;
using OAuch.OAuthThreatModel;
using OAuch.OAuthThreatModel.Consequences;
using OAuch.OAuthThreatModel.Enrichers;
using OAuch.OAuthThreatModel.Flows;
using OAuch.OAuthThreatModel.Threats;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Results {
    /// <summary>
    /// This class is an optimized version to calculate the threat model report
    /// </summary>
    public class ThreatModelReport {
        public ThreatModelReport(IList<TestResult> allResults, IList<ThreatReport> threatReports) {
            this.Empty128 = CreateEmptyVector128();

            CalculateModelDependencies(allResults, threatReports);

            

            /*
                elke consequence heeft een BitId
                elk ModelElement heeft een Precondition vector en een consequence vector

                consequences toevoegen => or operatie met state
                checken met vulnerabilities => and operatie met vulnerability vector
                are preconditions met => and operatie met state
                AvailableElements => LinkedList
            */
        }
        private void CalculateModelDependencies(IList<TestResult> allResults, IList<ThreatReport> threatReports) {
            var context = new CalculationContext(allResults, threatReports);
            // Create structures that hold ConsequenceType data
            context.ConsequenceIndices = new Dictionary<ConsequenceType, int>();
            context.Consequences = ConsequenceTypes.All.ToArray();
            context.ConsequenceBitIds = new Vector128<byte>[context.Consequences.Length];
            context.VulnerabilityBitIds = this.Empty128;
            for (var i = 0; i < context.ConsequenceBitIds.Length; i++) {
                context.ConsequenceIndices[context.Consequences[i]] = i;
                context.ConsequenceBitIds[i] = CreateVector128(i);
                if (context.Consequences[i].IsVulnerability)
                    context.VulnerabilityBitIds = Vector128.BitwiseOr(context.VulnerabilityBitIds, context.ConsequenceBitIds[i]);
            }
            // Create structures that hold ModelElement data
            context.ElementIndices = new Dictionary<ModelElement, int>();
            context.ModelElements =
            [
                .. Flow.All.Where(c => c.IsRelevant(context)),
                .. OAuthThreatModel.Threats.Threat.All.Where(c => c.IsRelevant(context)),
                .. Enricher.All.Where(c => c.IsRelevant(context)),
            ];
            context.ModelElementVectors = new ModelElementVectors[context.ModelElements.Count];
            context.FlowVectors = new LinkedList<ModelElementVectors>();
            context.ThreatVectors = new LinkedList<ModelElementVectors>();
            for (var i = 0; i < context.ModelElementVectors.Length; i++) {
                var element = context.ModelElements[i];
                context.ElementIndices[element] = i;
                context.ModelElementVectors[i] = new ModelElementVectors(CreateVector128(i), element, CombineConsequences(context.ConsequenceIndices, element.DependsOn), CombineConsequences(context.ConsequenceIndices, element.Consequences));
                if (element is Flow) {
                    context.FlowVectors.AddLast(context.ModelElementVectors[i]);
                } else {
                    context.ThreatVectors.AddLast(context.ModelElementVectors[i]);
                }
            }
            
            // begin calculation recursive
            foreach (var flow in context.FlowVectors) {
                var state = flow.Consequences; // start state
                var currentChain = flow.BitId; // start of chain with selected flow
                BuildChain(context, currentChain, state, context.ThreatVectors);
            }
        }

        private struct Frame {
            public Vector128<byte> State;
            public Vector128<byte> CurrentChain;
        }

        private void BuildChain(CalculationContext context, Vector128<byte> currentChain, Vector128<byte> state, LinkedList<ModelElementVectors> remainingElements) {
            context.Debug++;
            var node = remainingElements.First;
            while (node != null) {
                var vectors = node.Value;
                if (Vector128.BitwiseAnd(state, vectors.Preconditions) == vectors.Preconditions) { // check if the preconditions are met
                    // try this item
                    var prev = node.Previous;
                    remainingElements.Remove(node);
                    // check for vuln.; if not found, recurse
                    var newChain = Vector128.BitwiseOr(currentChain, node.Value.BitId);
                    var newState = Vector128.BitwiseOr(state, node.Value.Consequences);
                    if (newState != state) { // if the state doesn't change, we don't need the new element; do not go into recursive subtree
                        if (Vector128.BitwiseAnd(context.VulnerabilityBitIds, newState) == this.Empty128) { // no vulnerability
                            BuildChain(context, newChain, newState, remainingElements);
                        } else { // vulnerability found
                            ReportChain(context, newChain);
                        }
                    }
                    // restore item
                    if (prev == null)
                        remainingElements.AddFirst(node);
                    else
                        remainingElements.AddAfter(prev, node);
                }
                node = node.Next;
            }
        }
        private void ReportChain(CalculationContext context, Vector128<byte> chain) {
            // make sure we don't have the same (or a better) chain already
            var node = context.Chains.First;
            while (node != null) { // loop through the existing nodes
                if (node.Value == chain)
                    return; // we already have the same chain

                var next = node.Next;
                var and = Vector128.BitwiseAnd(node.Value, chain);
                if (and == chain) { // chain is subset of existing
                    context.Chains.Remove(node);
                } else if (and == node.Value) { // existing is subset of chain
                    return; // the existing chain we already have is better
                }
                node = next;
            }

            // add the chain
            context.Chains.AddLast(chain);
        }


        private class CalculationContext : IThreatModelContext {
            public CalculationContext(IList<TestResult> allResults, IList<ThreatReport> threatReports) {
                // cache the testcase implementation results
                TestcaseResults = new Dictionary<string, bool>();
                foreach (var tc in allResults) {
                    if (tc.Outcome != null) {
                        switch (tc.Outcome) {
                            case TestOutcomes.SpecificationFullyImplemented:
                            case TestOutcomes.SpecificationPartiallyImplemented:
                                TestcaseResults[tc.TestId] = true;
                                break;
                            case TestOutcomes.SpecificationNotImplemented:
                                TestcaseResults[tc.TestId] = false;
                                break;
                        }
                    }
                }

                // cache the threat results
                UnmitigatedThreatResults = new Dictionary<string, bool>();
                foreach (var tr in threatReports) {
                    if (tr.Outcome != null) {
                        switch (tr.Outcome) {
                            case TestOutcomes.SpecificationNotImplemented:
                                UnmitigatedThreatResults[tr.Threat.Id] = true;
                                break;
                            case TestOutcomes.SpecificationPartiallyImplemented:
                            case TestOutcomes.SpecificationFullyImplemented:
                                UnmitigatedThreatResults[tr.Threat.Id] = false;
                                break;
                        }
                    }
                }
                ThreatReports = threatReports.ToDictionary(c => c.Threat.Id);
                Chains = new LinkedList<Vector128<byte>>();
            }

            public long Debug;

            // ConsequenceType
            public Dictionary<ConsequenceType, int> ConsequenceIndices;
            public ConsequenceType[] Consequences;
            public Vector128<byte>[] ConsequenceBitIds;
            public Vector128<byte> VulnerabilityBitIds;
            // ModelElement
            public Dictionary<ModelElement, int> ElementIndices;
            public List<ModelElement> ModelElements;
            public ModelElementVectors[] ModelElementVectors;
            public LinkedList<ModelElementVectors> FlowVectors;
            public LinkedList<ModelElementVectors> ThreatVectors; // also includes Enrichers
            // Results
            public LinkedList<Vector128<byte>> Chains;

            public Dictionary<string, bool> TestcaseResults;
            public Dictionary<string, bool> UnmitigatedThreatResults;
            public Dictionary<string, ThreatReport> ThreatReports;

            public IEnumerable<ConsequenceType> CurrentState => throw new NotImplementedException();
            public bool? IsTestcaseImplemented(string id) {
                if (TestcaseResults.TryGetValue(id, out var value))
                    return value;
                return null;
            }
            public bool? IsThreatNotMitigated(string id) {
                if (UnmitigatedThreatResults.TryGetValue(id, out var value))
                    return value;
                return null;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Vector128<byte> CombineConsequences(Dictionary<ConsequenceType, int> dict, ConsequenceType[] input) {
            Array.Clear(buffer128);
            for (int i = 0; i < input.Length; i++) {
                var position = dict[input[i]];
                var bl = position / 8;
                var pos = position % 8;
                buffer128[bl] = (byte)(1 << pos);
            }
            return Vector128.Create(buffer128);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Vector128<byte> CreateEmptyVector128() {
            Array.Clear(buffer128);
            return Vector128.Create(buffer128);
        }
        private Vector128<byte> Empty128;

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        //private Vector64<byte> CreateVector64(int position) {
        //    Array.Clear(buffer64);
        //    var bl = position / 8;
        //    var pos = position % 8;
        //    buffer64[bl] = (byte)(1 << pos);
        //    return Vector64.Create(buffer64);
        //}
        //private byte[] buffer64 = new byte[8];
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Vector128<byte> CreateVector128(int position) {
            Array.Clear(buffer128);
            var bl = position / 8;
            var pos = position % 8;
            buffer128[bl] = (byte)(1 << pos);
            return Vector128.Create(buffer128);
        }
        private byte[] buffer128 = new byte[16];
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool TestBit(Vector128<byte> source, int position) {
            var bl = position / 8;
            var pos = position % 8;
            var bte = Vector128.GetElement(source, bl);
            return (bte & (byte)(1 << pos)) > 0;
        }

        private struct ModelElementVectors {
            public ModelElementVectors(Vector128<byte> bitId, ModelElement element, Vector128<byte> preconditions, Vector128<byte> consequences) {
                this.BitId = bitId;
                this.Element = element;
                this.Preconditions = preconditions;
                this.Consequences = consequences;
            }
            public readonly Vector128<byte> BitId;
            public readonly ModelElement Element;
            public readonly Vector128<byte> Preconditions;
            public readonly Vector128<byte> Consequences;
        }
    }




    public class ThreatModelReportOrg {
        public ThreatModelReportOrg(IList<TestResult> allResults, IList<ThreatReport> threatReports) {
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
            context.Debug++;
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
            var tc = new ThreatChain(currentChain.ToList(), state.Where(c => c.IsVulnerability).ToArray());
            this.UnmitigatedVulnerabilities.AddLast(tc);
        }

        public LinkedList<ThreatChain> UnmitigatedVulnerabilities { get; }


        public class ThreatChain {
            public ThreatChain(IReadOnlyList<ModelElement> elements, ConsequenceType[] consequences) {
                this.ChainElements = elements;
                this.Consequences = consequences;
            }
            public IReadOnlyList<ModelElement> ChainElements { get; }
            public ConsequenceType[] Consequences { get; }

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
            public TMStateCollection() => _state = new LinkedList<ConsequenceType[]>();
            public void PushConsequences(ConsequenceType[] consequences) => _state.AddLast(consequences);
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
            private LinkedList<ConsequenceType[]> _state;
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

            public long Debug;

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
