using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class ClientCredentialsFlowSupportedTest : FlowSupportedTest {
        public ClientCredentialsFlowSupportedTest() : base(OAuthHelper.CLIENT_CREDENTIALS_FLOW_TYPE, typeof(ClientCredentialsFlowSupportedTestResult)) { }
        public override string Title => $"Is the client credentials grant supported";
        public override string Description => $"This test determines whether the server supports the client credentials grant.";
    }
    public class ClientCredentialsFlowSupportedTestResult : FlowSupportedTestResult {
        public ClientCredentialsFlowSupportedTestResult(string testId) : base(testId, typeof(ClientCredentialsFlowSupportedTestImplementation)) { }
    }
    public class ClientCredentialsFlowSupportedTestImplementation : FlowSupportedTestImplementation {
        public ClientCredentialsFlowSupportedTestImplementation(TestRunContext context, ClientCredentialsFlowSupportedTestResult result) 
            : base("Client Credentials grant", OAuthHelper.CLIENT_CREDENTIALS_FLOW_TYPE, context, result) { }
        protected override TokenProvider CreateProvider(TokenProviderSettings ps, TestRunContext tc) {
            return new ClientCredentialsTokenProvider(ps, tc);
        }
    }
}
