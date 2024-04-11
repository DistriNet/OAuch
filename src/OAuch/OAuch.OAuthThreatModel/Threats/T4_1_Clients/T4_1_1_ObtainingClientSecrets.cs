using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.Clients {
    public class T4_1_1_ObtainingClientSecretsFromApp : Threat {
        public override string Id => "6819_4_1_1";

        public override string Description => "Obtaining Client Secrets From Source Code or Binary";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Don't issue secrets to public clients or clients with inappropriate security policy",
            "Require user consent for public clients",
            "Use deployment-specific client secrets",
            "Revoke client secrets"
            ];
    }
    public class T4_1_1_ObtainingDeploymentSecrets : Threat {
        public override string Id => "6819_4_1_1";

        public override string Description => "Obtain a Deployment-Specific Secret";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Web server: Apply standard web server protection measures",
            "Native application: Store secrets in secure local storage",
            "Revoke client secrets"
            ];
    }
}
