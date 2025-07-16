using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsClientIdRequiredTest : Test {
        public override string Title => "Is client id required";
        public override string Description => "This test checks if the server requires the client id for non-confidential clients that exchange an authorization code.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsClientIdRequiredTestResult);
    }
    public class IsClientIdRequiredTestResult : TestResult {
        public IsClientIdRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsClientIdRequiredTestImplementation);
    }
    public class IsClientIdRequiredTestImplementation : TestImplementation {
        public IsClientIdRequiredTestImplementation(TestRunContext context, IsClientIdRequiredTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var basicContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretPost, // force post authentication
                    ClientCertificates = []
                }
            };
            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(basicContext,
                (f, p) => f.HasAuthorizationCodes && !p.Context.SiteSettings.IsConfidentialClient);
            if (provider == null) { // no non-confidential provider found
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with authorization codes that does not require client authentication");
                return;
            }

            var processor = new RemoveClientId();
            provider.Pipeline.AddAfter<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("Valid token received without presenting the client id");
            }
        }
        public class RemoveClientId : Processor<HttpRequest, HttpRequest> {
            public override Task<HttpRequest?> Process(HttpRequest value, IProvider tokenProvider, TokenResult tokenResult) {
                var dictionary = EncodingHelper.EncodedFormToDictionary(Encoding.UTF8.GetString(value.Content));
                dictionary.Remove("client_id");
                value.Content = EncodingHelper.FormUrlEncode(dictionary!);
                return Task.FromResult<HttpRequest?>(value);
            }
        }
    }
}
