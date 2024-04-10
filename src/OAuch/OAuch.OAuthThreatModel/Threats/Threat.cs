using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats {
    public abstract class Threat : ModelElement {
        /// <summary>
        /// The description of the countermeasures for the threat
        /// </summary>
        public abstract string[] Countermeasures { get; }

        public override bool IsRelevant(IThreatModelContext context, IEnumerable<ConsequenceType> state) {
            if (!base.IsRelevant(context, state))
                return false;
            if (context.IsThreatUnmitigated(this.Id) == false) // if the threat is unmitigated, it is relevant
                return true;
            return false;
        }
    }
}
