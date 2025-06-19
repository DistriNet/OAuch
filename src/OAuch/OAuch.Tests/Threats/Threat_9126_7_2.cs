using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.ParEndpoint;
using OAuch.Compliance.Tests.Revocation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Threats {
    public class Threat_9126_7_2 : Threat {
        public Threat_9126_7_2() {
            AddDependency<RFC9126SupportedTest>();
            AddMitigation(Mit<RequiresNewRedirectUriAuthTest>(1));
        }

        public override string Id => "9126_7_2";

        public override string Title => "Open Redirection";

        public override string Description => "An attacker could try to register a redirect URI pointing to a site under their control in order to obtain authorization codes or launch other attacks towards the user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC9126"];

        public override string LocationInDocument => "7.2.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
