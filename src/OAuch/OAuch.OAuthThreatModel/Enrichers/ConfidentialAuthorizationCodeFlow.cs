using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class ConfidentialAuthorizationCodeFlow : Enricher {
        public override string Id => "OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest";

        public override string Description => "The client is a confidential client because it uses a client secret.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.IsConfidentialClient];

        protected override bool? RelevancyResult => true;
    }
}
