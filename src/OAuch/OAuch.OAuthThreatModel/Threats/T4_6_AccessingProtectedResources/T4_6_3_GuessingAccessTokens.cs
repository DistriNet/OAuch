using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.AccessingProtectedResources {
    public class T4_6_3_GuessingAccessTokens : Threat {
        public override string Id => "6819_4_6_3";

        public override string Description => "Guessing Access Tokens";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Handle tokens should have a reasonable level of entropy",
            "Assertion (or self-contained token) token contents should be protected by a digital signature",
            "Security can be further strengthened by using a short access token duration"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}
