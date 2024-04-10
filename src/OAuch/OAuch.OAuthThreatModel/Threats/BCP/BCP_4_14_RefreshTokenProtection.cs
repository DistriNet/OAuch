using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_14_RefreshTokenProtection : Threat {
        public override string Id => "BCP_4_14";

        public override string Description => "Refresh Token Protection";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.RefreshTokenLeaked];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "For confidential clients, refresh tokens can only be used by the client for which they were issued",
            "The authorization server cryptographically binds the refresh token to a certain client instance",
            "The authorization server issues a new refresh token with every access token refresh response",
            "Refresh tokens SHOULD expire if the client has been inactive for some time"
            ];
    }
}
