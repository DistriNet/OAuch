using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsBasicAuthenticationSupportedTest : Test {
        public override string Title => "Is basic authentication supported";
        public override string Description => "This test verifies whether the token endpoint supports the basic authentication scheme (or a more secure authentication scheme) for clients that were issues a password.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsBasicAuthenticationSupportedTestResult);
    }
    public class IsBasicAuthenticationSupportedTestResult : TestResult {
        public IsBasicAuthenticationSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsBasicAuthenticationSupportedTestImplementation);
    }
    public class IsBasicAuthenticationSupportedTestImplementation : TestImplementation {
        public IsBasicAuthenticationSupportedTestImplementation(TestRunContext context, IsBasicAuthenticationSupportedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var basicContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with { 
                     ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretBasic
                }
            };
            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(basicContext,
                (f, p) => !string.IsNullOrEmpty(p.SiteSettings.DefaultClient.ClientSecret));
            if (provider == null) { // no provider that has the CreateTokenRequest stage and has a password
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that requires client authentication via a client secret");
                return; // no flows that use client authentication
            }
            // we have found a working provider with a password

            // check if the user is correctly authenticated
            if (this.Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.ClientSecretJwt
                   || this.Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt
                   || this.Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.ClientSecretBasic) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                return;
            }

            // the site uses post authentication by default; see if we can use basic authentication
            var tokenResult = await provider.GetToken();
            if (tokenResult.TokenResponse?.IsValid ?? false) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }
    }
}
