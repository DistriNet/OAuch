using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ClientCredentials {
    public class T4_4_4_1_ExposureOfSecrets : Threat {
        public override string Id => "6819_4_4_4_1";

        public override string Description => "Accidental Exposure of Secret at Client Site";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.MachineToMachine];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];
        public override string[] Countermeasures => [
            "Use digest authentication instead of plaintext credential processing"
            ];
    }
}
