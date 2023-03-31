using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsAsymmetricClientAuthenticationUsedTest : Test {
        public override string Title => "Does the server support asymmetric client authentication";
        public override string Description => "This test determines whether the server supports asymmetric client authentication, such as mTLS or 'private_key_jwt'.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsAsymmetricClientAuthenticationUsedTestResult);
    }
    public class IsAsymmetricClientAuthenticationUsedTestResult : TestResult {
        public IsAsymmetricClientAuthenticationUsedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsAsymmetricClientAuthenticationUsedTestImplementation);
    }
    public class IsAsymmetricClientAuthenticationUsedTestImplementation : TestImplementation {
        public IsAsymmetricClientAuthenticationUsedTestImplementation(TestRunContext context, IsAsymmetricClientAuthenticationUsedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }
        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var p = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(Context);
            if (p == null) {
                LogInfo("Could not find a working flow that uses the token endpoint");
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            if (Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt || Context.SiteSettings.Certificates.Count > 0) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
            return Task.CompletedTask;
        }
    }
}