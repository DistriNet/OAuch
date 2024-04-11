using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Flows {
    public class AuthorizationCodeFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.CodeFlowSupportedTest";

        public override string Description => "Authorization Code Flow";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.HasAuthorizationCode];
    }
}
