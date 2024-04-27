using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class ConfidentialClientAC : Enricher {
        public override string Id => "OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest";

        public override string Description => "The client is a confidential client because it uses a client secret.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.IsConfidentialClient];

        protected override bool? RelevancyResult => true;
    }
    public class ConfidentialClientPW : Enricher {
        public override string Id => "OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest";

        public override string Description => "The client is a confidential client because it uses a client secret.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientHoldsUserPassword];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.IsConfidentialClient];

        protected override bool? RelevancyResult => true;
    }
    public class ConfidentialClientCC : Enricher {
        public override string Id => "OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest";

        public override string Description => "The client is a confidential client because it uses a client secret.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.MachineToMachine];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.IsConfidentialClient];

        protected override bool? RelevancyResult => true;
    }
}
