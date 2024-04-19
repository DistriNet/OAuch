using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_6_UserSessionImpersonation : Threat {

        public override string Id => "6819_4_4_1_6";

        public override string Description => "User Session Impersonation";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];
        public override string[] Countermeasures => [
            "the redirect URI of the client should point to an HTTPS protected endpoint"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
    }
}
