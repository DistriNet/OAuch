using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_12_DoSAuthorizationCodes : Threat {

        public override string Id => "6819_4_4_1_12";

        public override string Description => "DoS Using Manufactured Authorization \"codes\"";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.DenialOfService];
        public override string[] Countermeasures => [
            "CSRF defense and the \"state\" parameter created with secure random codes should be deployed on the client side",
            "The client should suspend the access by a user account if the number of invalid authorization \"codes\" submitted by this user exceeds a certain threshold",
            "The authorization server should send an error response to the client reporting an invalid authorization \"code\" and rate-limit or disallow connections from clients whose number of invalid requests exceeds a threshold."
            ];
    }
}
