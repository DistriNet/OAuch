using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
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

namespace OAuch.Compliance.Tests.DeviceAuthEndpoint {
    public class UnrecognizedParameterAllowedTest : Test {
        public override string Title => "Does the device authorization server ignore unrecognized parameters";
        public override string Description => "This test checks if the device authorization server allows adding (unrecognized) parameters to the request. This can be important to support future extensions of the OAuth 2.0 protocol.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(UnrecognizedParameterAllowedTestResult);
    }
    public class UnrecognizedParameterAllowedTestResult : TestResult {
        public UnrecognizedParameterAllowedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(UnrecognizedParameterAllowedTestImplementation);
    }
    public class UnrecognizedParameterAllowedTestImplementation : TestImplementation {
        public UnrecognizedParameterAllowedTestImplementation(TestRunContext context, UnrecognizedParameterAllowedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<GetDeviceCodeParameters, bool, Dictionary<string, string?>>(this.Context);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the device authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var processor = new AddUnrecognizedParameter();
            provider.Pipeline.AddAfter<GetDeviceCodeParameters, bool, Dictionary<string, string?>>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken != null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }
        public class AddUnrecognizedParameter : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                value["hello"] = "world";
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
