using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class BearerTokens : Enricher {
        public override string Id => "OAuch.Compliance.Tests.ApiEndpoint.AreBearerTokensDisabledTest";

        public override string Description => "If we have an access token it is a (usable) bearer token";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.AccessTokenLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];

        protected override bool? RelevancyResult => false;
    }

    public class PublicClientBearerTokens : Enricher {

        public override string Id => "PublicClientBearerTokens";

        public override string Description => "A public client always uses bearer tokens.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientAuthenticationSidestepped, ConsequenceTypes.AccessTokenLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];
    }
}
