using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Jwt {
    public class SupportsJwtClientAuthenticationTest : Test {
        public override string Title => "Is JWT authentication implemented";
        public override string Description => "This test checks if the authorization server supports JWT authentication.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(SupportsJwtClientAuthenticationTestResult);
    }
    public class SupportsJwtClientAuthenticationTestResult : TestResult {
        public SupportsJwtClientAuthenticationTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(SupportsJwtClientAuthenticationTestImplementation);
    }
    public class SupportsJwtClientAuthenticationTestImplementation : TestImplementation {
        public SupportsJwtClientAuthenticationTestImplementation(TestRunContext context, SupportsJwtClientAuthenticationTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.ClientSecretJwt || Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt) {
                var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(Context);
                if (provider == null) {
                    Result.Outcome = TestOutcomes.Skipped;
                    LogInfo("Could not find a working provider that accesses the token endpoint");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo($"The authorization server supports authentication mechanism '{Context.SiteSettings.ClientAuthenticationMechanism}'");
                }
            } else { // client JWT authentication is not set up, but may be supported
                var jwtContext = this.Context with {
                    SiteSettings = this.Context.SiteSettings with {
                        ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretJwt
                    }
                };
                var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(jwtContext, (fact, prov) => !string.IsNullOrEmpty(prov.SiteSettings.DefaultClient.ClientSecret));
                if (provider == null) {
                    Result.Outcome = TestOutcomes.Skipped;
                    LogInfo("Could not find a working provider that accesses the token endpoint");
                    return;
                }

                var result = await provider.GetToken();
                if (result.AccessToken == null) {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The token endpoint did not return a valid token after authenticating the client with a JWT");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The token endpoint returned a valid token after authenticating the client with a JWT");
                }
            }
        }
    }
}
