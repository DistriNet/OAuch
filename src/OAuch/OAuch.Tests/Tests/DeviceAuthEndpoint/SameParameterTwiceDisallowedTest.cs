using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
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
    public class SameParameterTwiceDisallowedTest : Test {
        public override string Title => "Does the device authorization server allow multiple instances of the same parameter";
        public override string Description => "This test checks whether the device authorization server accepts authorization requests with parameters that are included more than once.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(SameParameterTwiceDisallowedTestResult);
    }
    public class SameParameterTwiceDisallowedTestResult : TestResult {
        public SameParameterTwiceDisallowedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(SameParameterTwiceDisallowedTestImplementation);
    }
    public class SameParameterTwiceDisallowedTestImplementation : TestImplementation {
        public SameParameterTwiceDisallowedTestImplementation(TestRunContext context, SameParameterTwiceDisallowedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<CreateDeviceCodeRequest, Dictionary<string, string?>, HttpRequest>(this.Context);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the device authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var processor = new DuplicateParameter();
            provider.Pipeline.AddAfter<CreateDeviceCodeRequest, Dictionary<string, string?>, HttpRequest>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }
        public class DuplicateParameter : Processor<HttpRequest, HttpRequest> {
            public override Task<HttpRequest?> Process(HttpRequest value, IProvider tokenProvider, TokenResult tokenResult) {
                value.Content = value.Content.DuplicateParameter();
                return Task.FromResult<HttpRequest?>(value);
            }
        }
    }
}