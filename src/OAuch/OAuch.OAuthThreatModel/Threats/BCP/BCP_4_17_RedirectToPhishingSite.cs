using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_17_RedirectToPhishingSiteTiFC : Threat {
        public override string Id => "BCP_4_17";

        public override string Description => "Authorization Server Redirecting to Phishing Site";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel]; // Must use the authorization endpoint

        public override ConsequenceType[] Consequences => [ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "The authorization server needs to decide whether it can trust the redirect URI or not. It could take into account URI analytics done internally or through some external service to evaluate the credibility and trustworthiness content behind the URI, and the source of the redirect URI and other client data.",
            ];
    }
    public class BCP_4_17_RedirectToPhishingSiteAC : Threat {
        public override string Id => "BCP_4_17";

        public override string Description => "Authorization Server Redirecting to Phishing Site";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode]; // Must use the authorization endpoint

        public override ConsequenceType[] Consequences => [ConsequenceTypes.Phishing];

        public override string[] Countermeasures => [
            "The authorization server needs to decide whether it can trust the redirect URI or not. It could take into account URI analytics done internally or through some external service to evaluate the credibility and trustworthiness content behind the URI, and the source of the redirect URI and other client data.",
            ];
    }
}
