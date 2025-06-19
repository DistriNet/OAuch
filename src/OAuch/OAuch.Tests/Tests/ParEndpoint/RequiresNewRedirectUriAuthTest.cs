using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class RequiresNewRedirectUriAuthTest : Test {
        public override string Title => "Does the authorization server require authentication for new redirect uri's";
        public override string Description => "This test checks whether the authorization server requires client authentication before accepting new redirect uri's when using PAR.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RequiresNewRedirectUriAuthTestResult);
    }
    public class RequiresNewRedirectUriAuthTestResult : TestResult<RedirectUriFullyMatchedTestInfo> {
        public RequiresNewRedirectUriAuthTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RequiresNewRedirectUriAuthTestImplementation);
    }
    public class RequiresNewRedirectUriAuthTestImplementation : AcceptsNewRedirectUriImplBase {
        public RequiresNewRedirectUriAuthTestImplementation(TestRunContext context, RequiresNewRedirectUriAuthTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par, AcceptsNewRedirectUriTestResult newUri, IsParAuthenticationRequiredTestResult authed) : base(context, result, flows, par, newUri, authed) { }

        public async override Task Run() {
            if (HasFailed<AcceptsNewRedirectUriTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (HasSucceeded<IsParAuthenticationRequiredTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped; // PAR without authentication is not allowed
                return;
            }

            if (!Context.SiteSettings.IsConfidentialClient) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented; // AcceptsNewRedirectUriTest succeeded without client authentication
                return;
            }

            // remove authentication
            var settings = Context.SiteSettings with {
                DefaultClient = Context.SiteSettings.DefaultClient with {
                    ClientSecret = null
                },
                ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretBasic
            };
            await Execute(settings);
            if (ExtraInfo.Result == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            switch (ExtraInfo.Result) {
                case RedirectUriMatchedResults.UserNotified:
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    break;
                case RedirectUriMatchedResults.RequestDenied:
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    break;
                case RedirectUriMatchedResults.ParameterIgnored:
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    break;
                case RedirectUriMatchedResults.RequestAllowed:
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    break;
            }
        }
    }
}
