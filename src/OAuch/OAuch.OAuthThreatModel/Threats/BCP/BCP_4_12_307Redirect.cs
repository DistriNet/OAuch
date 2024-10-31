using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_12_307Redirect : Threat {
        public override string Id => "BCP_4_12";

        public override string Description => "307 Redirect";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.Uses307Redirect];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PasswordLeaked];

        public override string[] Countermeasures => [
            "Authorization servers that redirect a request that potentially contains the user's credentials therefore MUST NOT use the HTTP 307 status code for redirection",
            "If an HTTP redirection is used for such a request, the authorization server SHOULD use HTTP status code 303"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}
