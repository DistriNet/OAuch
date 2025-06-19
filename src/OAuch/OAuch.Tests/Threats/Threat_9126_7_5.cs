using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.ParEndpoint;
using OAuch.Compliance.Tests.Pkce;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Threats {
    public class Threat_9126_7_5 : Threat {
        public Threat_9126_7_5() {
            AddDependency<RFC9126SupportedTest>();
            AddMitigation(Mit<IsPkceRequiredTest>(1));
            AddMitigation(Mit<NonceRequiredTest>(1));
            AddMitigation(Mit<StatePresentTest>(1));
        }

        public override string Id => "9126_7_5";

        public override string Title => "Request URI Swapping";

        public override string Description => "An attacker could capture the request URI from one request and then substitute it into a different authorization request.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC9126"];

        public override string LocationInDocument => "7.5.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Reasonable;
    }
}
