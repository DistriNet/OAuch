using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.AccessingProtectedResources {
    public class T4_6_6_LeakOfConfidentialData : Threat {
        public override string Id => "6819_4_6_6";

        public override string Description => "Leak of Confidential Data in HTTP Proxies";

        public override IReadOnlyList<ConsequenceType> DependsOn => [];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Clients and resource servers not using an OAuth HTTP authentication scheme should take care to use Cache-Control headers to minimize the risk that authenticated content is not protected",
            "Reducing scope and expiry time for access tokens can be used to reduce the damage in case of leaks"
            ];
    }
}
