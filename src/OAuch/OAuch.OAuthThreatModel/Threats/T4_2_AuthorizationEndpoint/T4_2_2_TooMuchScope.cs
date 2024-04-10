using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.AuthorizationEndpoint
{
    public class T4_2_2_TooMuchScope : Threat
    {
        public override string Description => "User Unintentionally Grants Too Much Access Scope";

        public override string Id => "6819_4_2_2";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "Explain the scope (resources and the permissions) the user is about to grant in an understandable way",
            "Narrow the scope, based on the client."
            ];
    }
}
