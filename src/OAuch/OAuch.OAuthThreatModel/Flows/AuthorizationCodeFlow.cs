using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Flows {
    public class AuthorizationCodeFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.CodeFlowSupportedTest";

        public override string Description => "Authorization Code Grant";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.HasAuthorizationCode, ConsequenceTypes.UsesAuthorizationServer];
    }
}
