using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.RefreshingAccessTokens {
    public class T4_5_2_RefreshTokensFromDatabase : Threat {
        public override string Id => "6819_4_5_2";

        public override string Description => "Obtaining Refresh Token from Authorization Server Database";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "Enforce credential storage protection best practices",
            "Bind token to client id, if the attacker cannot obtain the required id and secret",
            ];
    }
}
