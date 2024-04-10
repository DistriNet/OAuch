using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.Clients {
    public class T4_1_2_ObtainingRefreshTokensFromWebApp : Threat {
        public override string Id => "6819_4_1_2";

        public override string Description => "Obtain Refresh Token from Web Application";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "Standard web server protection measures",
            "Use strong client authentication (e.g., client_assertion/client_token) so the attacker cannot obtain the client secret required to exchange the tokens"
            ];
    }
    public class T4_1_2_ObtainingRefreshTokensFromNativeClient : Threat {
        public override string Id => "6819_4_1_2";

        public override string Description => "Obtain Refresh Token from Native Clients";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "Store secrets in secure storage",
            "Utilize device lock to prevent unauthorized device access"
            ];
    }
    public class T4_1_2_ObtainingRefreshTokensByStealingDevice : Threat {
        public override string Id => "6819_4_1_2";

        public override string Description => "Steal Device";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "Utilize device lock to prevent unauthorized device access",
            "Where a user knows the device has been stolen, they can revoke the affected tokens"
            ];
    }
    public class T4_1_2_ObtainingRefreshTokensByCloningDevice : Threat {
        public override string Id => "6819_4_1_2";

        public override string Description => "Clone Device";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "Utilize device lock to prevent unauthorized device access",
            "Combine refresh token request with device identification",
            "Refresh token rotation",
            "Where a user knows the device has been cloned, they can use refresh token revocation"
            ];
    }
}
