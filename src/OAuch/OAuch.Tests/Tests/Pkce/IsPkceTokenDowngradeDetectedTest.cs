using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Pkce {
    public class IsPkceTokenDowngradeDetectedTest : Test {
        public override string Title => "Is PKCE downgrade detected (token request)";
        public override string Description => "Attackers can downgrade PKCE protection without the server noticing. The authorization request used PKCE, but an attacker can downgrade this modifying the token request.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsPkceTokenDowngradeDetectedTestResult);
    }
    public class IsPkceTokenDowngradeDetectedTestResult : TestResult {
        public IsPkceTokenDowngradeDetectedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsPkceTokenDowngradeDetectedTestImplementation);
    }
    public class IsPkceTokenDowngradeDetectedTestImplementation : TestImplementation {
        public IsPkceTokenDowngradeDetectedTestImplementation(TestRunContext context, IsPkceTokenDowngradeDetectedTestResult result, HasSupportedFlowsTestResult flows, IsPkceImplementedTestResult implemented) : base(context, result, flows, implemented) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<IsPkceImplementedTestResult>()) {
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

            var pkceContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    PKCEDefault = selectedPkceType
                }
            };

            var provider = flows.CreateProvider(pkceContext, (fact, prov) => prov.FlowType == OAuthHelper.CODE_FLOW_TYPE);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("The authorization code grant is not working");
                return;
            }

            var processor = new DummyPKCEVerifier();
            provider.Pipeline.Replace<AddPKCEVerifier, Dictionary<string, string?>, Dictionary<string, string?>>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The token server detected the downgrade attack");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The token server did not notice that the token exchange used PKCE, whereas the authorization request did not.");
            }
        }
        public class DummyPKCEVerifier : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public DummyPKCEVerifier() { }
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                // do nothing :-)
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}