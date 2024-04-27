using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class M2MAuthentication : Enricher {
        public override string Id => "M2MAuthentication";

        public override string Description => "When using the client credentials grant, if the client does not use authentication, the attacker gains full access to the resources.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.MachineToMachine, ConsequenceTypes.IsPublicClient];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];
    }
}
