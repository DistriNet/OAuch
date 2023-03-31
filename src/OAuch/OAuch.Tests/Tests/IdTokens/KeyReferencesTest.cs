using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.IdTokens {
    public class KeyReferencesTest : Test {
        public override string Title => "Are references to keys communicated using discovery and registration parameters";
        public override string Description => "This test determines whether the identity token uses keys that are communicated in advance using Discovery and Registration parameters, instead of the JWS x5u, x5c, jku and jwk header claims.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(KeyReferencesTestResult);
    }
    public class KeyReferencesTestResult : TestResult {
        public KeyReferencesTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(KeyReferencesTestImplementation);
    }
    public class KeyReferencesTestImplementation : IdTokenInspectionTestImplementationBase {
        public KeyReferencesTestImplementation(TestRunContext context, KeyReferencesTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            var illegalKeys = new string[] { "x5u", "x5c", "jku", "jwk" };
            foreach (var illegalKey in illegalKeys) {
                if (idToken.Header.ContainsKey(illegalKey)) {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo($"The ID token uses the '{ illegalKey }' header parameter field, which is not allowed by the OpenID Connect standard.");
                }
            }
        }
    }
}
