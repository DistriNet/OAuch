using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_2_1 : Threat {
        public Threat_6819_4_2_1() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<HasValidCertificateTest>(1), 
                Mit<IsHttpsRequiredTest>(1),
                Mit<IsModernTlsSupportedTest>(1));
        }

        public override string Id => "6819_4_2_1";

        public override string Title => "Password Phishing by Counterfeit Authorization Server";

        public override string Description => "OAuth makes no attempt to verify the authenticity of the authorization server. A hostile party could take advantage of this by intercepting the client's requests and returning misleading or otherwise incorrect responses. This could be achieved using DNS or Address Resolution Protocol (ARP) spoofing.  Wide deployment of OAuth and similar protocols may cause users to become inured to the practice of being redirected to web sites where they are asked to enter their passwords. If users are not careful to verify the authenticity of these web sites before entering their credentials, it will be possible for attackers to exploit this practice to steal users' passwords.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.2.1.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
