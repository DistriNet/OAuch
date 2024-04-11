using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class StateLeaked : Enricher {
        public override string Id => "OAuch.Compliance.Tests.Pkce.IsPkceRequiredTest";

        public override string Description => "If the state is leaked, the attacker can sidestep session authentication";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.StateLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.SessionAuthenticationSidestepped];
        protected override bool? RelevancyResult => false;
    }
}
