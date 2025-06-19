using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.Other {
    public class RFC9126_7_2_OpenRedirection : Threat {
        public override string Id => "9126_7_2";

        public override string Description => "Open Redirection";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "The authorization server MUST only accept new redirect URIs in the pushed authorization request from authenticated clients.",
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}
