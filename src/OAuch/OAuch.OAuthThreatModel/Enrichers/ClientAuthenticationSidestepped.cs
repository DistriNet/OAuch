using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class ClientAuthenticationSidestepped : Enricher {
        public override string Id => "ClientAuthenticationSidestepped";

        public override string Description => "If the client authentication can be sidestepped, the client is essentially a public client.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.IsPublicClient];
    }
}
