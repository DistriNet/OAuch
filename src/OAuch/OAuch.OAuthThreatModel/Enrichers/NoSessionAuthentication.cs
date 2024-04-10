using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class NoSessionAuthentication : Enricher {
        public override string Id => "NoSessionAuthentication";

        public override string Description => "If the access token is sent in the front channel, the client must implement measures to ensure the access token is linked to the current session (e.g., through 'state' or 'nonce'). However, we assume the client does not implement these things correctly in OAuch.";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.SessionAuthenticationSidestepped];
    }
}
