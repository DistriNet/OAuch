using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    internal class PublicAuthorizationCodeFlow : Enricher {
        public override string Id => "OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest";

        public override string Description => "If the authorization code flow doesn't use a client secret, it is a public client";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        protected override bool? RelevancyResult => false;
    }
}
