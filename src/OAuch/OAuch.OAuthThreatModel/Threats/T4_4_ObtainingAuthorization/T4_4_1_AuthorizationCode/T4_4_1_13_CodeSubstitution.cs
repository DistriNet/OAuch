using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_13_CodeSubstitution : Threat {
        public override string Id => "6819_4_4_1_13";

        public override string Description => "Code Substitution (OAuth Login)";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "The authorization server must validate whether the particular authorization \"code\" has been issued to the particular client.",
            "If possible, the client shall be authenticated beforehand."
            ];
    }
}
