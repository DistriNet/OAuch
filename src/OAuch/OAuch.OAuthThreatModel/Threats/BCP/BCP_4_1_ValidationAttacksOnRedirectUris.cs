﻿using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP4_1_RedirectUriValidation {
    public class BCP_4_1_1_ValidationAttacksOnAuthorizationGrant : Threat {
        public override string Id => "BCP_4_1_1";
        public override string Description => "Redirect URI Validation Attacks on Authorization Code Grant";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "The authorization server MUST ensure that the two URIs are equal",
            "Web servers on which redirect URIs are hosted MUST NOT expose open redirectors",
            "Servers MAY prevent browsers from reattaching fragments to redirection URLs by attaching an arbitrary fragment identifier, for example #_, to URLs in Location headers"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];
    }
    public class BCP_4_1_2_ValidationAttacksOnImplicitGrant : Threat {
        public override string Id => "BCP_4_1_2";
        public override string Description => "Redirect URI Validation Attacks on Implicit Grant";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "The authorization server MUST ensure that the two URIs are equal",
            "Web servers on which redirect URIs are hosted MUST NOT expose open redirectors",
            "Servers MAY prevent browsers from reattaching fragments to redirection URLs by attaching an arbitrary fragment identifier, for example #_, to URLs in Location headers",
            "Clients SHOULD use the authorization code response type instead of response types causing access token issuance at the authorization endpoint"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];
    }
}
