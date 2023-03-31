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

namespace OAuch.Compliance.Tests.Pkce {

    public class IsPkceImplementedTest : Test {
        public override string Title => "Is PKCE implemented";
        public override string Description => "This test checks if the PKCE standard is properly implemented.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsPkceImplementedTestResult);
    }
    public class IsPkceImplementedTestResult : TestResult {
        public IsPkceImplementedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsPkceImplementedTestImplementation);
    }
    public class IsPkceImplementedTestImplementation : TestImplementation {
        public IsPkceImplementedTestImplementation(TestRunContext context, IsPkceImplementedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || !flows.HasFlow(OAuthHelper.CODE_FLOW_TYPE)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var workingPkceTypes = Context.State.Get<List<PKCESupportTypes>>(StateKeys.WorkingPkceTypes);
            PKCESupportTypes selectedPkceType;
            if (workingPkceTypes.Contains(PKCESupportTypes.Hash)) {
                selectedPkceType = PKCESupportTypes.Hash;
            } else if (workingPkceTypes.Contains(PKCESupportTypes.Plain)) {
                selectedPkceType = PKCESupportTypes.Plain;
            } else { // only none is working
                LogInfo("PKCE is not allowed on the server");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                return;
            }

            var pkceContext = this.Context with
            {
                SiteSettings = this.Context.SiteSettings with
                {
                    PKCEDefault = selectedPkceType
                }
            };

            var provider = flows.CreateProvider(pkceContext, (fact, prov) => prov.FlowType == OAuthHelper.CODE_FLOW_TYPE);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("The authorization code grant is not working");
                return;
            }

            var processor = new InvalidateVerifier();
            provider.Pipeline.AddAfter<AddPKCEVerifier, Dictionary<string, string?>, Dictionary<string, string?>>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server detected the invalid code verifier");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The token endpoint returned a valid token despite an invalid code verifier");
            }
        }
        public class InvalidateVerifier : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                var v = value["code_verifier"]!.ToCharArray();
                Array.Reverse(v);
                value["code_verifier"] = new string(v);
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
