using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_16_ClickjackingAC : Threat {
        public override string Id => "BCP_4_16";

        public override string Description => "Clickjacking";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "Authorization servers SHOULD use Content Security Policy (CSP) level 2 [W3C.CSP-2] or greater",
            "Avoidance of iFrames during authorization can be enforced on the server side by using the X-FRAME-OPTIONS header",
            "JavaScript frame-busting techniques can be used but may not be effective in all browsers"
            ];
    }
    public class BCP_4_16_ClickjackingTiFC : Threat {
        public override string Id => "BCP_4_16";

        public override string Description => "Clickjacking";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "Authorization servers SHOULD use Content Security Policy (CSP) level 2 [W3C.CSP-2] or greater",
            "Avoidance of iFrames during authorization can be enforced on the server side by using the X-FRAME-OPTIONS header",
            "JavaScript frame-busting techniques can be used but may not be effective in all browsers"
            ];
    }
}
