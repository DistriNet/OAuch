using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.Clients {
    public class T4_1_3_ObtainingAccessTokens : Threat {
        public override string Id => "6819_4_1_3";

        public override string Description => "Obtaining Access Tokens";

        public override IReadOnlyList<ConsequenceType> DependsOn => [];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Keep access tokens in transient memory and limit grants",
            "Limit token scope",
            "Keep access tokens in private memory or apply same protection means as for refresh tokens",
            "Keep access token lifetime short"
            ];
    }
}
