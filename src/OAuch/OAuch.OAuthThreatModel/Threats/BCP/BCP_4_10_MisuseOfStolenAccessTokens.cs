using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_10_MisuseOfStolenAccessTokens : Threat {
        public override string Id => "BCP_4_10";

        public override string Description => "Misuse of Stolen Access Tokens";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.AccessTokenLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];

        public override string[] Countermeasures => [
            "Sender-Constrained Access Tokens",
            "Audience-Restricted Access Tokens"
            ];
    }
}
