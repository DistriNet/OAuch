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
    public class IsAccessTokenHashCorrectTest : Test {
        public override string Title => "Is the at_hash claim correct";
        public override string Description => "This test determines whether the value of the at_hash claim is correct.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsAccessTokenHashCorrectTestResult);
    }
    public class IsAccessTokenHashCorrectTestResult : TestResult {
        public IsAccessTokenHashCorrectTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsAccessTokenHashCorrectTestImplementation);
    }
    public class IsAccessTokenHashCorrectTestImplementation : TestImplementation {
        public IsAccessTokenHashCorrectTestImplementation(TestRunContext context, IsAccessTokenHashCorrectTestResult result, OpenIdSupportedTestResult oidc)
            : base(context, result, oidc) { }

        public override Task Run() {
            if (HasFailed<OpenIdSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var idTokens = TokenHelper.GetAllTokenResults(Context).Where(vt => !string.IsNullOrEmpty(vt.IdentityToken));
            foreach (var idToken in idTokens) {
                var jwtIdToken = JsonWebToken.CreateFromString(idToken?.IdentityToken, Context.Log);
                string? hashInIdToken = jwtIdToken?.Claims.AccessTokenHash;
                if (jwtIdToken != null && hashInIdToken != null) {
                    string? computedHash = null;
                    var hash = jwtIdToken.Header.Algorithm?.Hash;
                    if (idToken?.AccessToken == null) {
                        LogInfo("The identity token contains an 'at_hash' claim, but no access token is present in the authorization response");
                    } else {
                        if (hash != null) {
                            var hashed = hash.ComputeHash(Encoding.ASCII.GetBytes(idToken.AccessToken));
                            computedHash = EncodingHelper.Base64UrlEncode(hashed, 0, hashed.Length / 2);
                            LogInfo("Received an access token from the server with the value: " + idToken.AccessToken);
                        } else {
                            LogInfo("Unable to recreate the access token hash, because the ID token did not include a (supported) algorithm claim.");
                        }
                    }
                    if (computedHash == null) {
                        LogInfo("The hash of the access token in the ID token is not what is expected", computedHash, hashInIdToken);
                        Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    } else if (computedHash == hashInIdToken) {
                        LogInfo("The ID token contains a valid access token hash");
                        Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    } else { 
                        LogInfo("The ID token contains the hash of the access token, but the value is wrong", computedHash, hashInIdToken);
                        Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    }
                    return Task.CompletedTask;
                }
            }
            LogInfo("No identity tokens found with an at_hash claim");
            Result.Outcome = TestOutcomes.Skipped;
            return Task.CompletedTask;
        }
    }
}
