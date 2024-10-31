﻿using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_15_ResourceOwnerImpersonation : Threat {
        public override string Id => "BCP_4_15";

        public override string Description => "Client Impersonating Resource Owner";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientCanChooseId];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "The authorization server SHOULD NOT allow clients to influence their client_id or any claim that could cause confusion with a genuine resource owner",
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}
