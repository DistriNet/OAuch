using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Security.Authentication;

namespace OAuch.Compliance.Tests.IdTokens {
    public class ClientSecretLongEnoughTest : Test {
        public override string Title => "Is the client secret long enough";
        public override string Description => "This test determines whether the client secret is long enough. Client secret values must contain at least the minimum of number of octets required for MAC keys for the particular algorithm used.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(ClientSecretLongEnoughTestResult);
    }
    public class ClientSecretLongEnoughTestResult : TestResult<ClientSecretLongEnoughExtraInfo> {
        public ClientSecretLongEnoughTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(ClientSecretLongEnoughTestImplementation);
        public override float? ImplementationScore {
            get {
                if (this.ExtraInfo?.HashBits == null || this.ExtraInfo.SecretBits == null)
                    return base.ImplementationScore;
                return Math.Min(this.ExtraInfo.SecretBits.Value / this.ExtraInfo.HashBits.Value, 1f);
            }
        }
    }
    public class ClientSecretLongEnoughExtraInfo {
        public float? SecretBits { get; set; }
        public float? HashBits { get; set; }
    }
    public class ClientSecretLongEnoughTestImplementation : IdTokenInspectionTestImplementationBase {
        public ClientSecretLongEnoughTestImplementation(TestRunContext context, ClientSecretLongEnoughTestResult result, OpenIdSupportedTestResult oidc) : base(context, result, oidc) { }
        protected override void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken) {
            var client = Context.SiteSettings.GetClient(flowType);
            if (string.IsNullOrEmpty(client.ClientSecret) || idToken.Header.Algorithm?.IsAsymmetric != false) {
                Result.Outcome = TestOutcomes.Skipped;
                return; // public client, or confidential client that uses PKE
            }

            var hs = idToken.Header.Algorithm?.Hash?.HashSize;
            if (hs == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            Result.Outcome = client.ClientSecret.Length >= hs / 8 ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
        }
    }
}
