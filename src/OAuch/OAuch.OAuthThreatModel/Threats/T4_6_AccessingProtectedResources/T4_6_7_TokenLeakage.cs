using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.AccessingProtectedResources {
    public class T4_6_7_TokenLeakage : Threat {
        public override string Id => "6819_4_6_7";

        public override string Description => "Token Leakage via Log Files and HTTP Referrers";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Use Authorization headers or POST parameters instead of URI request parameters",
            "Set logging configuration appropriately",
            "Prevent unauthorized persons from access to system log files",
            "Abuse of leaked access tokens can be prevented by enforcing authenticated requests",
            "The impact of token leakage may be reduced by limiting scope and duration and by enforcing one-time token usage",
            ];
    }
}
