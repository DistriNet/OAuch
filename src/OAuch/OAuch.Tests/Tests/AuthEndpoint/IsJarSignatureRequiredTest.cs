using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.ParEndpoint;
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
    public class IsJarSignatureRequiredTest : Test {
        public override string Title => "Is the JAR signature required";
        public override string Description => "This test checks whether the signature on the JWT in the request_uri parameter is required.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsJarSignatureRequiredTestResult);
    }
    public class IsJarSignatureRequiredTestResult : TestResult {
        public IsJarSignatureRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsJarSignatureRequiredTestImplementation);
    }
    public class IsJarSignatureRequiredTestImplementation : TestImplementation {
        public IsJarSignatureRequiredTestImplementation(TestRunContext context, IsJarSignatureRequiredTestResult result, HasSupportedFlowsTestResult flows, IsJarSupportedTestResult jar) : base(context, result, flows, jar) { }

        public async override Task Run() {
            if (HasFailed<IsJarSupportedTestResult>()) { // no JAR support
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var prov = flows.CreateProviderWithStage<RewriteAsJarJwt, Dictionary<string, string?>, Dictionary<string, string?>>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the JAR standard (weird, should not happen here, because we know JAR is supported)
                return;
            }
            prov.Pipeline.Replace<RewriteAsJarJwt, Dictionary<string, string?>, Dictionary<string, string?>>(new RemoveJarSignature());

            var result = await prov.GetToken();
            if (result.AccessToken == null && result.IdentityToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server detected the missing signature.");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server issued a valid token despite a missing signature.");
            }
        }
        class RemoveJarSignature : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
                var settings = provider.SiteSettings with {
                    UseRequestParameter = true, // force JAR (if it's not enabled by default)
                    RequestSigningKey = null    // without a signature
                };
                OAuthHelper.RewriteAsJarJwt(settings, value);
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
