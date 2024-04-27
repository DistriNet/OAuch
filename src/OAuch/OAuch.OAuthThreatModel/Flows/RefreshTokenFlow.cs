using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Flows {
    public class RefreshTokenFlow : Flow {
        public override string Id => "OAuch.Compliance.Tests.Features.HasRefreshTokensTest";

        public override string Description => "Refresh Token Grant";

        public override ConsequenceType[] Consequences => [ConsequenceTypes.HasRefreshToken];
    }
}
