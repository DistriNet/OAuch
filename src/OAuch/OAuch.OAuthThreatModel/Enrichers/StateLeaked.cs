using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class StateLeaked : Enricher {
        public override string Id => "OAuch.Compliance.Tests.Pkce.IsPkceRequiredTest";

        public override string Description => "If the state is leaked, the attacker can sidestep session authentication";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.StateLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.SessionAuthenticationSidestepped];
        protected override bool? RelevancyResult => false;
    }
}
