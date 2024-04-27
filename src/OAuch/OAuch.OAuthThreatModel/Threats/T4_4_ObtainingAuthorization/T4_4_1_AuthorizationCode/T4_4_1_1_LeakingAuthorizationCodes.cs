using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_1_LeakingAuthorizationCodes : Threat {
        public override string Description => "Eavesdropping or Leaking Authorization \"codes\"";

        public override string Id => "6819_4_4_1_1";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "The authorization server as well as the client must ensure that these transmissions are protected using transport-layer mechanisms such as TLS.",
            "The authorization server will require the client to authenticate wherever possible, so the binding of the authorization \"code\" to a certain client can be validated in a reliable way",
            "Use short expiry time for authorization \"codes\"",
            "The authorization server should enforce a one-time usage restriction",
            "If an authorization server observes multiple attempts to redeem an authorization \"code\", the authorization server may want to revoke all tokens granted based on the authorization \"code\"",
            "In the absence of these countermeasures, reducing scope and expiry time  for access tokens can be used to reduce the damage in case of leaks.",
            "The client server may reload the target page of the redirect URI in order to automatically clean up the browser cache."
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker, AttackerTypes.WebAttacker];
    }
}
