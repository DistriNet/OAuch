using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.RefreshingAccessTokens {
    public class T4_5_4_RefreshTokenPhishing : Threat {
        public override string Id => "6819_4_5_4";

        public override string Description => "Refresh Token Phishing by Counterfeit Authorization Server";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "Utilize server authentication"
            ];
    }
}
