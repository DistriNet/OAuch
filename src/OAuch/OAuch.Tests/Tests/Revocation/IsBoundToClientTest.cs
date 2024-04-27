using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Revocation {
    public class IsBoundToClientTest : Test {
        public override string Title => "Is revocation bound to a specific client";
        public override string Description => "This test checks if the revocation endpoint only revokes tokens that are bound to the authenticated client.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsBoundToClientTestResult);
    }
    public class IsBoundToClientTestResult : TestResult {
        public IsBoundToClientTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsBoundToClientTestImplementation);
    }
    public class IsBoundToClientTestImplementation : TestImplementation {
        public IsBoundToClientTestImplementation(TestRunContext context, IsBoundToClientTestResult result, HasSupportedFlowsTestResult flows, RFC7009SupportedTestResult revocation, CanAccessTokensBeRevokedTestResult at, CanRefreshTokensBeRevokedTestResult rt) : base(context, result, flows, revocation, at, rt) { }

        public async override Task Run() {
            bool at = HasSucceeded<CanAccessTokensBeRevokedTestResult>(), rt = HasSucceeded<CanRefreshTokensBeRevokedTestResult>();
            if (HasFailed<RFC7009SupportedTestResult>() || !(at || rt)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (string.IsNullOrEmpty(Context.SiteSettings.AlternativeClient.ClientId)) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("This test requires an alternative client identifier");
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, rt, false, false, false);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow");
                return;
            }

            var result = await provider.GetToken();
            if (result.RefreshToken == null && result.AccessToken == null) {
                Result.Outcome = TestOutcomes.Failed;
                LogInfo("Provider did not return a refresh or access token");
                return; // should not happen
            }

            var alternativeSettings = Context.SiteSettings with {
                DefaultClient = Context.SiteSettings.AlternativeClient
            };
            var revoker = provider.CreateRevocationProvider(alternativeSettings)!;

            bool succeeded;
            if (rt && result.RefreshToken != null)
                succeeded = await revoker!.RevokeToken(result.RefreshToken, true);
            else if (at && result.AccessToken != null)
                succeeded = await revoker!.RevokeToken(result.AccessToken, false);
            else {
                Result.Outcome = TestOutcomes.Failed;
                return; // weird
            }

            if (succeeded) {
                LogInfo("The server accepted the revocation request with the wrong client id");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                LogInfo("The server rejected the revocation request with the wrong client id");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
