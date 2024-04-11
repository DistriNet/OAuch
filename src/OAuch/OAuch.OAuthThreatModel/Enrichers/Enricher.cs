using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public abstract class Enricher : ModelElement {
        /// <summary>
        /// true if the testcase referenced in Id must be implemented, false if it should not be implemented,
        /// null if the test case is a dummy placeholder name
        /// </summary>
        protected virtual bool? RelevancyResult { get; } = null;

        public override bool IsRelevant(IThreatModelContext context) {
            return context.IsTestcaseImplemented(this.Id) == RelevancyResult;
        }

        public static IList<Enricher> All { 
            get {
                if (_allEnrichers == null) {
                    _allEnrichers = FindElements<Enricher>();
                }
                return _allEnrichers;
            }
        }
        private static IList<Enricher>? _allEnrichers;
    }
}
