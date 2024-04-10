using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.RefreshingAccessTokens {
    public class T4_5_3_OnlineGuessing : Threat {
        public override string Id => "6819_4_5_3";

        public override string Description => "Obtaining Refresh Token by Online Guessing";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "Bind token to client id, because the attacker would guess the matching client id, too",
            "Authenticate the client; this adds another element that the attacker has to guess"
            ];
    }
}
