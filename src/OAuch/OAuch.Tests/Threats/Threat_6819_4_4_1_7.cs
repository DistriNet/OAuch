using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_1_7 : Threat {
        public Threat_6819_4_4_1_7() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation(Mit<RedirectUriPathMatchedTest>(1), 
                Mit<RedirectUriConfusionTest>(1), 
                Mit<CodePollutionTest>(1), 
                Mit<RedirectUriCheckedTest>(1));
            AddMitigation(Mit<RedirectUriFullyMatchedTest>(1));
        }

        public override string Id => "6819_4_4_1_7";

        public override string Title => "Authorization 'code' Leakage through Counterfeit Client";

        public override string Description => "The attacker leverages the authorization 'code' grant type in an attempt to get another user (victim) to log in, authorize access to his/her resources, and subsequently obtain the authorization 'code' and inject it into a client application using the attacker's account. The goal is to associate an access authorization for resources of the victim with the user account of the attacker on a client site. The attacker abuses an existing client application and combines it with his own counterfeit client web site.  The attacker depends on the victim expecting the client application to request access to a certain resource server.  The victim, seeing only a normal request from an expected application, approves the request.  The attacker then uses the victim's authorization to gain access to the information unknowingly authorized by the victim.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.7.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
