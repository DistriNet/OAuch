using OAuch.Compliance.Tests;
using OAuch.OAuthThreatModel;
using OAuch.OAuthThreatModel.Consequences;
using OAuch.OAuthThreatModel.Enrichers;
using OAuch.OAuthThreatModel.Flows;
using OAuch.OAuthThreatModel.Threats;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using ConsequenceId = System.Runtime.Intrinsics.Vector128<byte>;
using ConsequenceIdOps = System.Runtime.Intrinsics.Vector128;
using ElementId = System.Runtime.Intrinsics.Vector256<byte>;
using ElementIdOps = System.Runtime.Intrinsics.Vector256;

namespace OAuch.Compliance.Results {
    /// <summary>
    /// This class is an optimized version to calculate the threat model report
    /// </summary>
    public class AttackReport {
        private const int ElementByteLength = 32; // change this if the Vector type to represent elements changes
        private const int ConsequenceByteLength = 16; // change this if the Vector type to represent consequences changes


        public AttackReport(IList<TestResult> allResults, IList<ThreatReport> threatReports, IEnumerable<string> selectedElements, ThreatModelContext? existingContext = null) {
            this.EmptyConsequence = CreateEmptyConsequence();
            CalculateModelDependencies(allResults, threatReports, selectedElements, existingContext);
        }
        [MemberNotNull(nameof(_chains), nameof(Context))]
        private void CalculateModelDependencies(IList<TestResult> allResults, IList<ThreatReport> threatReports, IEnumerable<string> selectedElements, ThreatModelContext? existingContext = null) {
            CalculationContext context;
            if (existingContext == null)
                context = new CalculationContext(allResults, threatReports);
            else
                context = new CalculationContext(existingContext, threatReports);
            // Create structures that hold ConsequenceType data
            // Every ConsequenceType receives a corresponding BitId (exponent of 2 number, stored in a bit Vector)
            context.ConsequenceIndices = [];
            context.Consequences = ConsequenceTypes.All.ToArray();
            context.ConsequenceBitIds = new ConsequenceId[context.Consequences.Length];
            context.VulnerabilityBitIds = this.EmptyConsequence;
            for (var i = 0; i < context.ConsequenceBitIds.Length; i++) {
                context.ConsequenceIndices[context.Consequences[i]] = i;
                context.ConsequenceBitIds[i] = CreateConsequence(i);
                if (context.Consequences[i].IsVulnerability)
                    context.VulnerabilityBitIds = ConsequenceIdOps.BitwiseOr(context.VulnerabilityBitIds, context.ConsequenceBitIds[i]);
            }
            // Create structures that hold ModelElement data
            // Every ModelElement receives a corresponding BitId (exponent of 2 number, stored in a bit Vector)
            context.ElementIndices = [];
            context.ModelElements =
            [
                .. Flow.All.Where(c => c.IsRelevant(context) && selectedElements.Contains(c.Id)),
                .. OAuthThreatModel.Threats.Threat.All.Where(c => c.IsRelevant(context) && selectedElements.Contains(c.Id) && c.Attackers.Any(at => selectedElements.Contains(at.Id))),
                .. Enricher.All.Where(c => c.IsRelevant(context))
            ];

            context.ModelElementVectors = new ModelElementVectors[context.ModelElements.Count];
            context.FlowVectors = new LinkedList<ModelElementVectors>();
            context.ThreatVectors = new LinkedList<ModelElementVectors>();
            for (var i = 0; i < context.ModelElementVectors.Length; i++) {
                var element = context.ModelElements[i];
                context.ElementIndices[element] = i;
                context.ModelElementVectors[i] = new ModelElementVectors(CreateElement(i), element, CombineConsequences(context, element.DependsOn), CombineConsequences(context, element.Consequences));
                if (element is Flow) {
                    context.FlowVectors.AddLast(context.ModelElementVectors[i]);
                } else {
                    context.ThreatVectors.AddLast(context.ModelElementVectors[i]);
                }
            }

            // begin calculation (recursive)
            foreach (var flow in context.FlowVectors) {
                var state = flow.Consequences; // start state
                var currentChain = flow.BitId; // start of chain with selected flow
                if (!BuildChain(context, currentChain, state, context.ThreatVectors, 0))
                    break; // search canceled (too many results)
            }

            // consolidate results
            var chains = new List<AttackChain>();
            foreach (var chain in context.Chains) {
                var c = CreateAttackChain(context, chain);
                if (c != null)
                    chains.Add(c);
            }
            _chains = chains.OrderByDescending(c => c.RiskScore).ToList();
            this.Context = context;
        }
        private static AttackChain? CreateAttackChain(CalculationContext context, ElementId currentChain) {
            // reconstruct the elements in a chain
            var elements = new List<ModelElement>();
            foreach (var mev in context.ModelElementVectors) {
                if (ElementIdOps.BitwiseAnd(currentChain, mev.BitId) == mev.BitId) {
                    elements.Add(mev.Element);
                }
            }
            elements = [.. elements.OrderBy(c => (c is Enricher) ? 1 : 2)]; // make sure the enrichers are first in the list; we want to use them as soon as possible in the chain
            // reconstruct the order of the chain
            var state = new List<ConsequenceType>();
            var flow = elements.First(c => c is Flow);
            state.AddRange(flow.Consequences);
            var orderedElements = new List<ModelElement>() { flow };
            elements.Remove(flow);
            while (!state.Any(c => c.IsVulnerability)) {
                for (int i = 0; i < elements.Count; i++) {
                    if (elements[i].DependsOn.All(c => state.Contains(c))) { // is precondition met?
                        // select it
                        state.AddRange(elements[i].Consequences); // update state
                        orderedElements.Add(elements[i]); // add to chain
                        elements.RemoveAt(i); // remove from remaining options
                        break;
                    }
                }
            }
            // calculate risk by multiplying the completeness scores of the threats
            float riskScore = 0;
            bool first = true;
            foreach (var el in orderedElements) {
                var th = el as Threat;
                if (th != null) {
                    if (context.ThreatReports.TryGetValue(th.Id, out var report) && report.CompletenessScore != null) {
                        if (first) {
                            first = false;
                            riskScore = 1 - report.CompletenessScore.Value;
                        } else {
                            riskScore = riskScore * (1 - report.CompletenessScore.Value);
                        }
                    }
                }
            }

            return new AttackChain(flow, orderedElements, state.Where(c => c.IsVulnerability).ToArray(), riskScore);
        }
        private bool BuildChain(CalculationContext context, ElementId currentChain, ConsequenceId state, LinkedList<ModelElementVectors> remainingElements, int depth) {
            var node = remainingElements.First;
            while (node != null) {
                var vectors = node.Value;
                if (ConsequenceIdOps.BitwiseAnd(state, vectors.Preconditions) == vectors.Preconditions) { // check if the preconditions are met
                    // try this item
                    var prev = node.Previous;
                    remainingElements.Remove(node);
                    // check for vuln.; if not found, recurse
                    var newChain = ElementIdOps.BitwiseOr(currentChain, node.Value.BitId);
                    var newState = ConsequenceIdOps.BitwiseOr(state, node.Value.Consequences);
                    if (newState != state) { // if the state doesn't change, we don't need the new element; do not go into recursive subtree
                        if (ConsequenceIdOps.BitwiseAnd(context.VulnerabilityBitIds, newState) == this.EmptyConsequence) { // no vulnerability
                            if (!BuildChain(context, newChain, newState, remainingElements, depth + 1))
                                return false; // search canceled (too many results)
                        } else { // vulnerability found
                            if (!ReportChain(context, newChain))
                                return false; // search canceled (too many results)
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
            return true;
        }
        private static bool ReportChain(CalculationContext context, ElementId chain) {
            // make sure we don't have the same (or a better) chain already
            var node = context.Chains.First;
            while (node != null) { // loop through the existing nodes
                if (node.Value == chain)
                    return true; // we already have the same chain

                var next = node.Next;
                var and = ElementIdOps.BitwiseAnd(node.Value, chain);
                if (and == chain) { // chain is subset of existing
                    context.Chains.Remove(node);
                } else if (and == node.Value) { // existing is subset of chain
                    return true; // the existing chain we already have is better
                }
                node = next;
            }

            // the current chain is new (or better than a previous one); add the chain
            context.Chains.AddLast(chain);
            return context.Chains.Count < MaxResults;
        }

        public IReadOnlyList<AttackChain> AttackChains => _chains;

        private IReadOnlyList<AttackChain> _chains;
        public const int MaxResults = 50;

        public ThreatModelContext Context { get; private set; }


        private class CalculationContext : ThreatModelContext {
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
            public CalculationContext(ThreatModelContext existingContext, IList<ThreatReport> threatReports) : base(existingContext) {
                ThreatReports = threatReports.ToDictionary(c => c.Threat.Id);
                Chains = new LinkedList<ElementId>();
            }
            public CalculationContext(IList<TestResult> allResults, IList<ThreatReport> threatReports) : base(allResults, threatReports) {
                ThreatReports = threatReports.ToDictionary(c => c.Threat.Id);
                Chains = new LinkedList<ElementId>();
            }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

            // ConsequenceType
            public Dictionary<ConsequenceType, int> ConsequenceIndices;
            public ConsequenceType[] Consequences;
            public ConsequenceId[] ConsequenceBitIds;
            public ConsequenceId VulnerabilityBitIds;
            // ModelElement
            public Dictionary<ModelElement, int> ElementIndices;
            public List<ModelElement> ModelElements;
            public ModelElementVectors[] ModelElementVectors;
            public LinkedList<ModelElementVectors> FlowVectors;
            public LinkedList<ModelElementVectors> ThreatVectors; // also includes Enrichers
            // Results
            public LinkedList<ElementId> Chains;

            public Dictionary<string, ThreatReport> ThreatReports;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ConsequenceId CombineConsequences(CalculationContext context, ConsequenceType[] input) {
            var allBitIds = CreateEmptyConsequence();
            for (int i = 0; i < input.Length; i++) {
                var bitId = context.ConsequenceBitIds[context.ConsequenceIndices[input[i]]]; // get the corresponding bitId of the ConsequenceType
                allBitIds = ConsequenceIdOps.BitwiseOr(allBitIds, bitId);
            }
            return allBitIds;
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ConsequenceId CreateEmptyConsequence() {
            Array.Clear(bufferConsequence);
            return ConsequenceIdOps.Create(bufferConsequence);
        }
        private readonly ConsequenceId EmptyConsequence;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ConsequenceId CreateConsequence(int position) {
            Array.Clear(bufferConsequence);
            var bl = position / 8;
            var pos = position % 8;
            bufferConsequence[bl] = (byte)(1 << pos);
            return ConsequenceIdOps.Create(bufferConsequence);
        }
        private readonly byte[] bufferConsequence = new byte[ConsequenceByteLength];

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ElementId CreateElement(int position) {
            Array.Clear(bufferElement);
            var bl = position / 8;
            var pos = position % 8;
            bufferElement[bl] = (byte)(1 << pos);
            return ElementIdOps.Create(bufferElement);
        }
        private readonly byte[] bufferElement = new byte[ElementByteLength];

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        //private bool TestBit(Vector128<byte> source, int position) {
        //    var bl = position / 8;
        //    var pos = position % 8;
        //    var bte = Vector128.GetElement(source, bl);
        //    return (bte & (byte)(1 << pos)) > 0;
        //}

        private readonly struct ModelElementVectors {
            public ModelElementVectors(ElementId bitId, ModelElement element, ConsequenceId preconditions, ConsequenceId consequences) {
                this.BitId = bitId;
                this.Element = element;
                this.Preconditions = preconditions;
                this.Consequences = consequences;
            }
            public readonly ElementId BitId;
            public readonly ModelElement Element;
            public readonly ConsequenceId Preconditions;
            public readonly ConsequenceId Consequences;
        }
    }
    public class ThreatModelContext : IThreatModelContext {
        public ThreatModelContext(ThreatModelContext existingContext) {
            this.TestcaseResults = existingContext.TestcaseResults;
            this.UnmitigatedThreatResults = existingContext.UnmitigatedThreatResults;
        }
        public ThreatModelContext(IList<TestResult> allResults, IList<ThreatReport> threatReports) {
            // cache the testcase implementation results
            TestcaseResults = [];
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
            UnmitigatedThreatResults = [];
            foreach (var tr in threatReports) {
                if (tr.Outcome != null) {
                    switch (tr.Outcome) {
                        case TestOutcomes.SpecificationNotImplemented:
                        case TestOutcomes.SpecificationPartiallyImplemented:
                            UnmitigatedThreatResults[tr.Threat.Id] = true;
                            break;
                        case TestOutcomes.SpecificationFullyImplemented:
                            UnmitigatedThreatResults[tr.Threat.Id] = false;
                            break;
                    }
                }
            }
        }
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
        public Dictionary<string, bool> TestcaseResults;
        public Dictionary<string, bool> UnmitigatedThreatResults;
    }
    public class AttackChain {
        public AttackChain(ModelElement flow, IReadOnlyList<ModelElement> elements, IReadOnlyList<ConsequenceType> vulnerabilities, float risk) {
            this.Flow = flow;
            this.Elements = elements;
            this.Vulnerabilities = vulnerabilities;
            this.RiskScore = risk;
        }
        public ModelElement Flow { get; }
        public IReadOnlyList<ModelElement> Elements { get; }
        public IEnumerable<ConsequenceType> Vulnerabilities { get; }
        public float RiskScore { get; } // number between [0..1] that represents the risk for this attack chain (combination of the risks of the individual threats in the chain); 0 = low risk, 1 = high risk
    }
}