using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ResourceOwnerPasswordCredentials {
    public class T4_4_3_1_ExposureOfPasswords : Threat {
        public override string Id => "6819_4_4_3_1";

        public override string Description => "Accidental Exposure of Passwords at Client Site";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.ClientHoldsUserPassword];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PasswordLeaked];
        public override string[] Countermeasures => [
            "Use other flows that do not rely on the client's cooperation for secure resource owner credential handling",
            "Use digest authentication instead of plaintext credential processing"
            ];
    }
}
