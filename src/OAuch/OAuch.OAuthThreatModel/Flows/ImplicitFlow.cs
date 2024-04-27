using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Flows {
    public class ImplicitFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.TokenFlowSupportedTest";

        public override string Description => "Implicit Grant";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.HasTokenInFrontChannel, ConsequenceTypes.UsesAuthorizationServer];
    }
}
