using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class NoSessionAuthentication : Enricher {
        public override string Id => "NoSessionAuthentication";

        public override string Description => "If the access token is sent in the front channel, the client must implement measures to ensure the access token is linked to the current session (e.g., through 'state' or 'nonce'). However, in this analysis, we assume that clients are secure by default.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.SessionAuthenticationSidestepped];
    }
}
