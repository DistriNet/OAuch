using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_11_1_OpenRedirectionAC : Threat {
        public override string Id => "BCP_4_11_1";

        public override string Description => "Client as Open Redirector";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AuthorizationCodeLeaked, ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "Require clients to register full redirect URI"
            ];
    }
    public class BCP_4_11_1_OpenRedirectionTiFC : Threat {
        public override string Id => "BCP_4_11_1";

        public override string Description => "Client as Open Redirector";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AccessTokenLeaked, ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "Require clients to register full redirect URI"
            ];
    }

    public class BCP_4_11_2_OpenRedirection : Threat {
        public override string Description => "Authorization Server as Open Redirector";

        public override string Id => "BCP_4_11_2";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "Require clients to register any full redirect URIs",
            "Don't redirect to a redirect URI if the client identifier or redirect URI can't be verified"
            ];
    }
}
