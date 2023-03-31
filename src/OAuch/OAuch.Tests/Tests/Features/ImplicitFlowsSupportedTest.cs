using Newtonsoft.Json;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Unity.Resolution;

namespace OAuch.Compliance.Tests.Features {
    public abstract class ImplicitFlowSupportedTest : FlowSupportedTest {
        public ImplicitFlowSupportedTest(string responseType, Type resultType) : base(responseType, resultType) { }
        public override string Title => $"Is the implicit grant (response type = '{ this.FlowType }') supported";
        public override string Description => $"This test determines whether the server supports the implicit grant (with response type '{ this.FlowType }').";
    }
    public abstract class ImplicitFlowSupportedTestImplementation : FlowSupportedTestImplementation {
        public ImplicitFlowSupportedTestImplementation(string responseType, TestRunContext context, FlowSupportedTestResult result)
            : base($"Implicit grant (response type '{ responseType }')", 
                  responseType, context, result) { }
        protected override TokenProvider CreateProvider(TokenProviderSettings ps, TestRunContext tc) {
            return new ImplicitTokenProvider(ps, tc);
        }
    }


    ////////////////
    ///  TOKEN
    ////////////////
    public class TokenFlowSupportedTest : ImplicitFlowSupportedTest {
        public TokenFlowSupportedTest() : base(OAuthHelper.TOKEN_FLOW_TYPE, typeof(TokenFlowSupportedTestResult)) {}
    }
    public class TokenFlowSupportedTestResult : FlowSupportedTestResult {
        public TokenFlowSupportedTestResult(string testId) : base(testId, typeof(TokenFlowSupportedTestImplementation)) { }
    }
    public class TokenFlowSupportedTestImplementation : ImplicitFlowSupportedTestImplementation {
        public TokenFlowSupportedTestImplementation(TestRunContext context, TokenFlowSupportedTestResult result) : base(OAuthHelper.TOKEN_FLOW_TYPE, context, result) { }
    }

    ////////////////
    ///  IDTOKEN TOKEN
    ////////////////
    public class IdTokenTokenFlowSupportedTest : ImplicitFlowSupportedTest {
        public IdTokenTokenFlowSupportedTest() : base(OAuthHelper.IDTOKEN_TOKEN_FLOW_TYPE, typeof(IdTokenTokenFlowSupportedTestResult)) { }
    }
    public class IdTokenTokenFlowSupportedTestResult : FlowSupportedTestResult {
        public IdTokenTokenFlowSupportedTestResult(string testId) : base(testId, typeof(IdTokenTokenFlowSupportedTestImplementation)) { }
    }
    public class IdTokenTokenFlowSupportedTestImplementation : ImplicitFlowSupportedTestImplementation {
        public IdTokenTokenFlowSupportedTestImplementation(TestRunContext context, IdTokenTokenFlowSupportedTestResult result) : base(OAuthHelper.IDTOKEN_TOKEN_FLOW_TYPE, context, result) { }
    }

    ////////////////
    ///  IDTOKEN
    ////////////////
    public class IdTokenFlowSupportedTest : ImplicitFlowSupportedTest {
        public IdTokenFlowSupportedTest() : base(OAuthHelper.IDTOKEN_FLOW_TYPE, typeof(IdTokenFlowSupportedTestResult)) { }
    }
    public class IdTokenFlowSupportedTestResult : FlowSupportedTestResult {
        public IdTokenFlowSupportedTestResult(string testId) : base(testId, typeof(IdTokenFlowSupportedTestImplementation)) { }
    }
    public class IdTokenFlowSupportedTestImplementation : ImplicitFlowSupportedTestImplementation {
        public IdTokenFlowSupportedTestImplementation(TestRunContext context, IdTokenFlowSupportedTestResult result) : base(OAuthHelper.IDTOKEN_FLOW_TYPE, context, result) { }
    }
}