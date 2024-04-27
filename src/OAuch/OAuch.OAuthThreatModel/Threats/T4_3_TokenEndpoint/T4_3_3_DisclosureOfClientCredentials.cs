using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.TokenEndpoint {
    public class T4_3_3_DisclosureOfClientCredentials : Threat {
        public override string Description => "Disclosure of Client Credentials during Transmission";

        public override string Id => "6819_4_3_3";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "The transmission of client credentials must be protected using transport-layer mechanisms such as TLS",
            "Use alternative authentication means that do not require the sending of plaintext credentials over the wire"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
    }
}
