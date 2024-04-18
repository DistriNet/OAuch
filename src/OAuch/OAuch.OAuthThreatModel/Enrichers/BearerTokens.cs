using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    //THIS IS BCP_4_10
    //public class BearerTokens : Enricher {
    //    public override string Id => "OAuch.Compliance.Tests.ApiEndpoint.AreBearerTokensDisabledTest";

    //    public override string Description => "The access tokens for this service are bearer tokens (i.e., they do not require client authentication to be used).";

    //    public override ConsequenceType[] DependsOn => [ConsequenceTypes.AccessTokenLeaked];

    //    public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];

    //    protected override bool? RelevancyResult => false;
    //}

    public class PublicClientBearerTokens : Enricher {

        public override string Id => "PublicClientBearerTokens";

        public override string Description => "A public client always uses bearer tokens.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.IsPublicClient, ConsequenceTypes.AccessTokenLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];
    }
}
