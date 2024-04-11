using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_9_ClickjackingAC : Threat {
        public override string Id => "6819_4_4_1_9";

        public override string Description => "Clickjacking Attack against Authorization";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];
        public override string[] Countermeasures => [
            "Avoidance of iFrames during authorization can be enforced on the server side by using the X-FRAME-OPTIONS header",
            "JavaScript frame-busting techniques can be used but may not be effective in all browsers"
            ];
    }
    public class T4_4_1_9_ClickjackingTiFC : Threat {
        public override string Id => "6819_4_4_1_9";

        public override string Description => "Clickjacking Attack against Authorization";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];
        public override string[] Countermeasures => [
            "Avoidance of iFrames during authorization can be enforced on the server side by using the X-FRAME-OPTIONS header",
            "JavaScript frame-busting techniques can be used but may not be effective in all browsers"
            ];
    }
}
