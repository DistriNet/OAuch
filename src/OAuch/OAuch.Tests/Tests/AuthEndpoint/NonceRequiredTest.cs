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
    public class NonceRequiredTest : Test {
        public override string Title => "Is the nonce parameter required";
        public override string Description => "This test checks whether the authorization server requires the presence of the nonce parameter when using the OpenId implicit flow.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(NonceRequiredTestResult);
    }
    public class NonceRequiredTestResult : TestResult {
        public NonceRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(NonceRequiredTestImplementation);
    }
    public class NonceRequiredTestImplementation : TestImplementation {
        public NonceRequiredTestImplementation(TestRunContext context, NonceRequiredTestResult result, HasSupportedFlowsTestResult flows)
            : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(this.Context,
                (f, p) => f.FlowType == OAuthHelper.IDTOKEN_TOKEN_FLOW_TYPE || f.FlowType == OAuthHelper.IDTOKEN_FLOW_TYPE);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the OpenID implicit flow");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var processor = new RemoveNonce();
            provider.Pipeline.AddAfter<AddNonce, Dictionary<string, string?>, Dictionary<string, string?>>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }
        public class RemoveNonce : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                value.Remove("nonce");
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
