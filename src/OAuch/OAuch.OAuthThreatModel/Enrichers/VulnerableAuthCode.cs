using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class VulnerableAuthCode : Enricher {
        public override string Id => "VulnerableAuthCode";

        public override string Description => "A leaked authorization code can be exchanged for an access token if the client is public and there is no session authentication (e.g., through PKCE).";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.AuthorizationCodeLeaked, ConsequenceTypes.SessionAuthenticationSidestepped, ConsequenceTypes.IsPublicClient];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];
    }
}
