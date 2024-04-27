using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class VulnerableAuthCode : Enricher {
        public override string Id => "VulnerableAuthCode";

        public override string Description => "A leaked authorization code can be exchanged for an access token if the client is public and there is no session authentication (e.g., through PKCE).";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.AuthorizationCodeLeaked, ConsequenceTypes.SessionAuthenticationSidestepped, ConsequenceTypes.IsPublicClient];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];
    }
}
