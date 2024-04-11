using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Flows {
    public class ClientCredentialsFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.ClientCredentialsFlowSupportedTest";

        public override string Description => "Client Credentials Flow";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.MachineToMachine];
    }
}
