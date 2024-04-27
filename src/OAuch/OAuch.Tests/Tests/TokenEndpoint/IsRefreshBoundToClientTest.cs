using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsRefreshBoundToClientTest : Test {
        public override string Title => "Is the refresh token bound to a client";
        public override string Description => "This test checks if the refresh token is bound to a specific client.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsRefreshBoundToClientTestResult);
    }
    public class IsRefreshBoundToClientTestResult : TestResult {
        public IsRefreshBoundToClientTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsRefreshBoundToClientTestImplementation);
    }
    public class IsRefreshBoundToClientTestImplementation : TestImplementation {
        public IsRefreshBoundToClientTestImplementation(TestRunContext context, IsRefreshBoundToClientTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            if (string.IsNullOrWhiteSpace(this.Context.SiteSettings.AlternativeClient.ClientId)) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("This test requires that an alternative client id is set up");
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, (f, p) => f.HasRefreshTokens);
            if (provider == null) { // no provider with refresh tokens found
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that returns refresh tokens");
                return;
            }

            var result = await provider.GetToken();
            if (result.RefreshToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider did not return refresh token");
                return; // should not happen
            }

            var am = Context.SiteSettings.ClientAuthenticationMechanism;
            if (am == ClientAuthenticationMechanisms.PrivateKeyJwt)
                am = ClientAuthenticationMechanisms.ClientSecretBasic;
            var postSettings = this.Context.SiteSettings with {
                ClientAuthenticationMechanism = am,
                Certificates = [],
                DefaultClient = Context.SiteSettings.AlternativeClient
            };
            var refreshProvider = provider.CreateRefreshProvider(postSettings);
            var refreshedResult = await refreshProvider.RefreshToken(result.RefreshToken);
            if (refreshedResult.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("No token was issued to the wrong client id");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("Valid token received after authenticating with wrong client id");
            }
        }
    }
}
