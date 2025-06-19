using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.ParEndpoint;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Threats {
    public class Threat_9126_7_3 : Threat {
        public Threat_9126_7_3() {
            AddDependency<RFC9126SupportedTest>();
            AddMitigation(Mit<IsRequestUriRevokedTest>(1));
        }

        public override string Id => "9126_7_3";

        public override string Title => "Request Object Replay";

        public override string Description => "An attacker could replay a request URI captured from a legitimate authorization request.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC9126"];

        public override string LocationInDocument => "7.3.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
