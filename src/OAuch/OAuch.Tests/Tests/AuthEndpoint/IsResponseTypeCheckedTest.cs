using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class IsResponseTypeCheckedTest : Test {
        public override string Title => "Does the authorization server check the response type";
        public override string Description => "This test checks if the authorization server requires a valid value for the response type parameter.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsResponseTypeCheckedTestResult);
    }
    public class IsResponseTypeCheckedTestResult : TestResult {
        public IsResponseTypeCheckedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsResponseTypeCheckedTestImplementation);
    }
    public class IsResponseTypeCheckedTestImplementation : TestImplementation {
        public IsResponseTypeCheckedTestImplementation(TestRunContext context, IsResponseTypeCheckedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<GetAuthParameters, bool, Dictionary<string, string?>>(this.Context);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var processor = new ChangeResponseTypeParameter();
            provider.Pipeline.AddAfter<GetAuthParameters, bool, Dictionary<string, string?>>(processor);

            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            var result = await provider.GetToken();
            if (result.AccessToken != null) {
                LogInfo("The authorization server accepts a non-existent response type");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                processor.DeleteParameter = true;
                result = await provider.GetToken();
                if (result.AccessToken != null) {
                    LogInfo("The authorization server accepts an authorization request without a response type");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                }
            }
        }
        public class ChangeResponseTypeParameter : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public bool DeleteParameter { get; set; }
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                if (DeleteParameter)
                    value.Remove("response_type");
                else
                    value["response_type"] = "oauch";
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
