using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Flows {
    public class ClientCredentialsFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.ClientCredentialsFlowSupportedTest";

        public override string Description => "Client Credentials Grant";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.MachineToMachine];
    }
}
