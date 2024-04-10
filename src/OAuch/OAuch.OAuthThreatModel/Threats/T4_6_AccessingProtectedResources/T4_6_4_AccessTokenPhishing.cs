using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.AccessingProtectedResources {
    public class T4_6_4_AccessTokenPhishing : Threat {
        public override string Id => "6819_4_6_4";

        public override string Description => "Access Token Phishing by Counterfeit Resource Server";

        public override IReadOnlyList<ConsequenceType> DependsOn => [];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Clients should not make authenticated requests with an access token to unfamiliar resource servers, regardless of the presence of a secure channel",
            "Associate the endpoint URL of the resource server the client talked to with the access token",
            "Associate an access token with a client and authenticate the client with resource server requests",
            "Restrict the token scope and/or limit the token to a certain resource server"
            ];
    }
}
