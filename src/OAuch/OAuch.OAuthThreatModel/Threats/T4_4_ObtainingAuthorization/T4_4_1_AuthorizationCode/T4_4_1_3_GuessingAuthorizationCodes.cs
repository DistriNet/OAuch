﻿using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_3_GuessingAuthorizationCodes : Threat {
        public override string Description => "Online Guessing of Authorization \"codes\"";

        public override string Id => "6819_4_4_1_3";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "Handle-based tokens must use high entropy",
            "Assertion-based tokens should be signed",
            "Authenticate the client; this adds another value that the attacker has to guess",
            "Bind the authorization \"code\" to the redirect URI; this adds another value that the attacker has to guess",
            "Use short expiry time for tokens"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
