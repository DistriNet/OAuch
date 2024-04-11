using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Flows {
    public class PasswordFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest";

        public override string Description => "Password Flow";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientHoldsUserPassword];
    }
}
