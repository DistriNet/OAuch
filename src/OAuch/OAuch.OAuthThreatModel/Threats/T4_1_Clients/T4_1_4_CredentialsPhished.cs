using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.Clients {
    public class T4_1_4_CredentialsPhished : Threat {
        public override string Id => "6819_4_1_4";

        public override string Description => "End-User Credentials Phished Using Compromised or Embedded Browser";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PasswordLeaked];

        public override string[] Countermeasures => [
            "Client applications should avoid directly asking users for their credentials",
            "Client applications could be validated prior to publication in an application market for users to access",
            "Client developers should not write client applications that collect authentication information directly from users and should instead delegate this task to a trusted system component, e.g., the system browser"
            ];
    }
}
