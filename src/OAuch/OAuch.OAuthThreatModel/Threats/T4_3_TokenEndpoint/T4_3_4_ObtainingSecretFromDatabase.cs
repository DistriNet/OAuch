﻿using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.TokenEndpoint {
    public class T4_3_4_ObtainingSecretFromDatabase : Threat {
        public override string Description => "Obtaining Client Secret from Authorization Server Database";

        public override string Id => "6819_4_3_4";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Enforce system security measures",
            "Enforce standard SQL injection countermeasures",
            "Ensure proper handling of credentials"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
