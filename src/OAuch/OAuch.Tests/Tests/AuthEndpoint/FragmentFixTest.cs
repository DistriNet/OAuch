using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class FragmentFixTest : Test {
        public override string Title => "Does the server attach a fragment";
        public override string Description => "This test checks whether the server attaches an arbitrary fragment identifier to prevent browsers from reattaching fragments to redirection URLs.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(FragmentFixTestResult);
    }
    public class FragmentFixTestResult : TestResult {
        public FragmentFixTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(FragmentFixTestImplementation);
    }
    public class FragmentFixTestImplementation : TestImplementation {
        public FragmentFixTestImplementation(TestRunContext context, FragmentFixTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(this.Context, (fact, prov) => prov.FlowType == OAuthHelper.CODE_FLOW_TYPE);
            if (provider == null) {
                LogInfo("The authorization code flow doesn't work");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var processor = new InspectCallback();
            provider.Pipeline.AddBefore<GetServerResponseFromCallback, ICallbackResult?, ServerResponse>(processor);

            var result = await provider.GetToken();
            if (!result.IsValid) {
                Result.Outcome = TestOutcomes.Skipped;
                return; // weird
            }
            if (processor.HasFixedFragment == true) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }
        public class InspectCallback : Processor<ICallbackResult?, ICallbackResult?> {
            public bool? HasFixedFragment { get; set; }
            public override Task<ICallbackResult?> Process(ICallbackResult? value, IProvider tokenProvider, TokenResult tokenResult) {
                if (value != null && Uri.TryCreate(value.Url, UriKind.Absolute, out var uri)) {
                    this.HasFixedFragment = uri.Fragment.TrimStart('#').Length != 0;
                }
                return Task.FromResult(value);
            }
        }
    }
}
