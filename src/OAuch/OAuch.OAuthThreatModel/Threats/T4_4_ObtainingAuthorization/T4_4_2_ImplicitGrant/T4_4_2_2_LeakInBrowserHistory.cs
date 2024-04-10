using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ImplicitGrant {
    public class T4_4_2_2_LeakInBrowserHistory : Threat {
        public override string Id => "6819_4_4_2_2";

        public override string Description => "Access Token Leak in Browser History";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Use short expiry time for tokens",
            "Make responses non-cacheable"
            ];
    }
}
