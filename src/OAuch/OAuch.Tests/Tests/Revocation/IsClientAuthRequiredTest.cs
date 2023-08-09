using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Revocation {
    public class IsClientAuthRequiredTest : Test {
        public override string Title => "Does revocation require client authentication";
        public override string Description => "This test checks if the revocation endpoint requires client authentication.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsClientAuthRequiredTestResult);
    }
    public class IsClientAuthRequiredTestResult : TestResult {
        public IsClientAuthRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsClientAuthRequiredTestImplementation);
    }
    public class IsClientAuthRequiredTestImplementation : TestImplementation {
        public IsClientAuthRequiredTestImplementation(TestRunContext context, IsClientAuthRequiredTestResult result, HasSupportedFlowsTestResult flows, RFC7009SupportedTestResult revocation, CanAccessTokensBeRevokedTestResult at, CanRefreshTokensBeRevokedTestResult rt) : base(context, result, flows, revocation, at, rt) { }

        public async override Task Run() {
            bool at = HasSucceeded<CanAccessTokensBeRevokedTestResult>(), rt = HasSucceeded<CanRefreshTokensBeRevokedTestResult>();
            if (HasFailed<RFC7009SupportedTestResult>() || !(at || rt)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context,
                (fact, tp) => tp.SiteSettings.IsConfidentialClient, 
                rt, false, false, false);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that uses a confidential client");
                return;
            }

            var result = await provider.GetToken();
            if (result.RefreshToken == null && result.AccessToken == null) {
                Result.Outcome = TestOutcomes.Failed;
                LogInfo("Provider did not return a refresh or access token");
                return; // should not happen
            }

            var revoker = provider.CreateRevocationProvider()!;
            var rr = revoker.Pipeline.FindProcessor<CreateRevocationRequest>()!;
            rr.AddClientAuthenticationMethod = (provider, request, pars) => { }; // do not send client authentication

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
                LogInfo("The server accepted the unauthenticated revocation request");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else { 
                LogInfo("The server rejected the unauthenticated revocation request");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
