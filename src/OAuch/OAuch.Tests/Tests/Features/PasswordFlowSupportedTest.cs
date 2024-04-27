using OAuch.Protocols.OAuth2;
using OAuch.Shared;

namespace OAuch.Compliance.Tests.Features {
    public class PasswordFlowSupportedTest : FlowSupportedTest {
        public PasswordFlowSupportedTest() : base(OAuthHelper.PASSWORD_FLOW_TYPE, typeof(PasswordFlowSupportedTestResult)) { }
        public override string Title => $"Is the password grant supported";
        public override string Description => $"This test determines whether the server supports the password grant.";
    }
    public class PasswordFlowSupportedTestResult : FlowSupportedTestResult {
        public PasswordFlowSupportedTestResult(string testId) : base(testId, typeof(PasswordFlowSupportedTestImplementation)) { }
    }
    public class PasswordFlowSupportedTestImplementation : FlowSupportedTestImplementation {
        public PasswordFlowSupportedTestImplementation(TestRunContext context, PasswordFlowSupportedTestResult result)
            : base("Password grant", OAuthHelper.PASSWORD_FLOW_TYPE, context, result) { }
        protected override TokenProvider CreateProvider(TokenProviderSettings ps, TestRunContext tc) {
            return new PasswordTokenProvider(ps, tc);
        }
    }

}
