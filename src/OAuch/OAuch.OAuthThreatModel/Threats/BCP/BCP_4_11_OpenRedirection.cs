using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_11_1_OpenRedirectionAC : Threat {
        public override string Id => "BCP_4_11_1";

        public override string Description => "Client as Open Redirector";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked, ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "Require clients to register full redirect URI"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];
    }
    public class BCP_4_11_1_OpenRedirectionTiFC : Threat {
        public override string Id => "BCP_4_11_1";

        public override string Description => "Client as Open Redirector";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked, ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "Require clients to register full redirect URI"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];
    }

    public class BCP_4_11_2_OpenRedirectionAC : Threat {
        public override string Description => "Authorization Server as Open Redirector";

        public override string Id => "BCP_4_11_2";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "Require clients to register any full redirect URIs",
            "Don't redirect to a redirect URI if the client identifier or redirect URI can't be verified"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
    public class BCP_4_11_2_OpenRedirectionTiFC : Threat {
        public override string Description => "Authorization Server as Open Redirector";

        public override string Id => "BCP_4_11_2";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "Require clients to register any full redirect URIs",
            "Don't redirect to a redirect URI if the client identifier or redirect URI can't be verified"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}
