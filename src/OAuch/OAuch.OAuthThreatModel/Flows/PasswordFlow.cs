using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Flows {
    public class PasswordFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest";

        public override string Description => "Password Grant";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientHoldsUserPassword];
    }
}
