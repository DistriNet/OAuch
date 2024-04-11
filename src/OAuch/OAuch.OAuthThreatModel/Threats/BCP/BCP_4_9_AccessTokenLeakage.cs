using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_9_AccessTokenLeakage : Threat {
        public override string Id => "BCP_4_9";

        public override string Description => "Access Token Leakage at the Resource Server";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientUsesMultipleResourceServers];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Sender-constrained access tokens SHOULD be used to prevent the attacker from replaying the access tokens on other resource servers",
            "Audience restriction SHOULD be used to prevent replay of captured access tokens on other resource servers",
            "The resource server MUST treat access tokens like other sensitive secrets and not store or transfer them in plain text"
            ];
    }
}
