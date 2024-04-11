using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class NonPKCEFlow : Enricher {
        public override string Id => "OAuch.Compliance.Tests.Pkce.IsPkceRequiredTest";

        public override string Description => "The authorization code flow does not require PKCE";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.SessionAuthenticationSidestepped];

        protected override bool? RelevancyResult => false;
    }
}
