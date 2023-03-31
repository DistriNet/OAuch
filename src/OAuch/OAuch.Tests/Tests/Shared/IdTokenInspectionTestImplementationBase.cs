using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public abstract class IdTokenInspectionTestImplementationBase : TestImplementation {
        public IdTokenInspectionTestImplementationBase(TestRunContext context, TestResult result, OpenIdSupportedTestResult oidc)
            : base(context, result, oidc) {}

        protected abstract void ProcessToken(string flowType, ValidToken fullTokenResult, JsonWebToken idToken);
        public override Task Run() {
            if (HasFailed<OpenIdSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var idToken = TokenHelper.GetAllTokenResults(Context).Where(vt => !string.IsNullOrEmpty(vt.IdentityToken)).FirstOrDefault();
            var jwtIdToken = JsonWebToken.CreateFromString(idToken?.IdentityToken, Context.Log);
            if (jwtIdToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            ProcessToken(idToken!.FlowType, idToken, jwtIdToken);
            return Task.CompletedTask;
        }
    }
}
