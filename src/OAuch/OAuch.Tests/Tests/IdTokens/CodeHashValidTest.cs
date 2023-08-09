using OAuch.Compliance.Tests.DocumentSupport;
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
    public class CodeHashValidTest : Test {
        public override string Title => "Is the c_hash claim correct";
        public override string Description => "This test determines whether the value of the c_hash claim is correct.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(CodeHashValidTestResult);
    }
    public class CodeHashValidTestResult : TestResult {
        public CodeHashValidTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(CodeHashValidTestImplementation);
    }
    public class CodeHashValidTestImplementation : TestImplementation {
        public CodeHashValidTestImplementation(TestRunContext context, CodeHashValidTestResult result, OpenIdSupportedTestResult oidc)
            : base(context, result, oidc) { }

        public override Task Run() {
            if (HasFailed<OpenIdSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var idTokens = TokenHelper.GetAllTokenResults(Context).Where(vt => !string.IsNullOrEmpty(vt.IdentityToken) && !string.IsNullOrEmpty(vt.AuthorizationCode));
            foreach (var idToken in idTokens) {
                var jwtIdToken = JsonWebToken.CreateFromString(idToken?.IdentityToken, Context.Log);
                string? hashInIdToken = jwtIdToken?.Claims.CodeHash;
                if (jwtIdToken != null && hashInIdToken != null) {
                    string? computedHash = null;
                    var hash = jwtIdToken.Header.Algorithm?.Hash;
                    if (idToken?.AuthorizationCode == null) {
                        LogInfo("The identity token contains an 'c_hash' claim, but no authorization code is present in the authorization response");
                    } else {
                        if (hash != null) {
                            var hashed = hash.ComputeHash(Encoding.ASCII.GetBytes(idToken.AuthorizationCode));
                            computedHash = EncodingHelper.Base64UrlEncode(hashed, 0, hashed.Length / 2);
                            LogInfo("Received an access token from the server with the value: " + idToken.AccessToken);
                        } else {
                            LogInfo("Unable to recreate the access token hash, because the ID token did not include a (supported) algorithm claim.");
                        }
                    }
                    if (computedHash == null) {
                        LogInfo("The hash of the authorization code in the ID token is not what is expected", computedHash, hashInIdToken);
                        Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    } else if (computedHash == hashInIdToken) {
                        LogInfo("The ID token contains a valid authorization code hash");
                        Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    } else {
                        LogInfo("The ID token contains the hash of the authorization code, but the value is wrong", computedHash, hashInIdToken);
                        Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    }
                    return Task.CompletedTask;
                }
            }
            LogInfo("No identity tokens found with a c_hash claim");
            Result.Outcome = TestOutcomes.Skipped;
            return Task.CompletedTask;
        }
    }
}
