using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.Clients {
    public class T4_1_5_OpenRedirectorsAC : Threat {
        public override string Id => "6819_4_1_5";

        public override string Description => "Open Redirectors on Client";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "Require clients to register full redirect URI"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
    public class T4_1_5_OpenRedirectorsTiFC : Threat {
        public override string Id => "6819_4_1_5";

        public override string Description => "Open Redirectors on Client";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Require clients to register full redirect URI"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}
