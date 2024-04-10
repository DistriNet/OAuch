using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel {
    public abstract class ModelElement {
        public abstract string Id { get; }
        public abstract string Description { get; }
        /// <summary>
        /// A list of all the ConsequenceTypes this ModelElement depends on. If one of these is missing, the ModelElement is not relevant.
        /// </summary>
        public abstract IReadOnlyList<ConsequenceType> DependsOn { get; }
        /// <summary>
        /// A list of all the consequences that this ModelElement has if it is relevant.
        /// </summary>
        public abstract IReadOnlyList<ConsequenceType> Consequences { get; }
        /// <summary>
        /// Checks if the ModelElement is relevant given the current context and state. This default implementation only checks whether the state contains all the DependsOn entries.
        /// </summary>
        /// <param name="context">An object that can be used as an oracle to see whether threats/testcases are relevant or not (i.e., is the threat not mitigated, or is the test case not met)</param>
        /// <param name="state">The list of consequence types that is already met.</param>
        /// <returns>true if the ModelElement is relevant, false if it can be discarded</returns>
        /// <remarks>This must be overridden in subclasses to perform additional relevancy checks.</remarks>
        public virtual bool IsRelevant(IThreatModelContext context, IEnumerable<ConsequenceType> state) {
            if (this.DependsOn == null)
                return true;
            foreach(var ct in this.DependsOn) {
                if (!state.Contains(ct))
                    return false;
            }
            return true;
        }
    }

    public interface IThreatModelContext {
        /// <summary>
        /// Checks for a given threat id whether the threat is unmitigated or not
        /// </summary>
        /// <param name="id">The threat id to check</param>
        /// <returns>true if it is unmitigated, false if it is mitigated, null if no information is available</returns>        
        bool? IsThreatUnmitigated(string id);
        /// <summary>
        /// Checks for a given testcase id whether the threat is unmitigated or not
        /// </summary>
        /// <param name="id">The testcase id to check</param>
        /// <returns>true if it is fully implemented, false if it is partially or not implemented, null if no information is available</returns>        
        bool? IsTestcaseImplemented(string id);
    }
}
