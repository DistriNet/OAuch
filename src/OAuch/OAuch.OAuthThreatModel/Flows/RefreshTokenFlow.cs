using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Flows {
    public class RefreshTokenFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.HasRefreshTokensTest";

        public override string Description => "Refresh Token Grant";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.HasRefreshToken];
    }
}
