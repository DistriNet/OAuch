using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ImplicitGrant {
    public class T4_4_2_4_ManipulationOfScripts : Threat {
        public override string Id => "6819_4_4_2_4";

        public override string Description => "Manipulation of Scripts";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked, ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "The authorization server should authenticate the server from which scripts are obtained",
            "The client should ensure that scripts obtained have not been altered in transport",
            "Introduce one-time, per-use secrets (e.g., \"client_secret\") values that can only be used by scripts in a small time window once loaded from a server"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];
    }
}
