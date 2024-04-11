using OAuch.OAuthThreatModel.Consequences;
using OAuch.OAuthThreatModel.Enrichers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Flows {
    public abstract class Flow : ModelElement {
        public override IReadOnlyList<ConsequenceType> DependsOn => [];
        /// <summary>
        /// Checks if the ModelElement is relevant given the current context and state. This default implementation only checks whether the state contains all the DependsOn entries.
        /// </summary>
        /// <param name="context">An object that can be used as an oracle to see whether threats/testcases are relevant or not (i.e., is the threat not mitigated, or is the test case not met)</param>
        /// <param name="state">The list of consequence types that is already met.</param>
        /// <returns>true if the ModelElement is relevant, false if it can be discarded</returns>
        /// <remarks>This must be overridden in subclasses to perform additional relevancy checks.</remarks>
        public override bool IsRelevant(IThreatModelContext context) {
            if (!base.IsRelevant(context)) // are the preconditions met?
                return false;
            return context.IsTestcaseImplemented(this.Id) == true;
        }

        public static IList<Flow> All {
            get {
                if (_allFlows == null) {
                    _allFlows = FindElements<Flow>();
                }
                return _allFlows;
            }
        }
        private static IList<Flow>? _allFlows;

    }
}
