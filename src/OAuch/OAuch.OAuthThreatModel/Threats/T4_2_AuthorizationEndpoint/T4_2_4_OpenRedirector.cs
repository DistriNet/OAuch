using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.AuthorizationEndpoint {
    public class T4_2_4_OpenRedirector : Threat {
        public override string Description => "Open Redirector";

        public override string Id => "6819_4_2_4";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.UsesAuthorizationServer]; // depends on a a flow that uses the authorization server

        public override ConsequenceType[] Consequences => [ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "Require clients to register any full redirect URIs",
            "Don't redirect to a redirect URI if the client identifier or redirect URI can't be verified"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}