using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_18_PostMessageAC : Threat {
        public override string Id => "BCP_4_18";

        public override string Description => "Attacks on In-Browser Communication Flows";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.UsesPostMessage, ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked, ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Authorization servers MUST send postMessages to trusted client receiver origins",
            "Wildcard origins like \"*\" in postMessage MUST NOT be used as attackers can use them to leak a victim's in-browser message to malicious origins",
            "Clients MUST prevent injection of in-browser messages on the client receiver endpoint",
            "Clients MUST utilize exact string matching to compare the initiator origin of an in-browser message with the authorization server origin"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
    public class BCP_4_18_PostMessageTiFC : Threat {
        public override string Id => "BCP_4_18";

        public override string Description => "Attacks on In-Browser Communication Flows";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.UsesPostMessage, ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Authorization servers MUST send postMessages to trusted client receiver origins",
            "Wildcard origins like \"*\" in postMessage MUST NOT be used as attackers can use them to leak a victim's in-browser message to malicious origins",
            "Clients MUST prevent injection of in-browser messages on the client receiver endpoint",
            "Clients MUST utilize exact string matching to compare the initiator origin of an in-browser message with the authorization server origin"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}
