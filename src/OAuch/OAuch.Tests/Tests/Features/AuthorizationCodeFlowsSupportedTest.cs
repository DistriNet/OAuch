using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public abstract class HybridCodeFlowSupportedTest : FlowSupportedTest {
        public HybridCodeFlowSupportedTest(string responseType, Type resultType) : base(responseType, resultType) { }
        public override string Title => $"Is the hybrid grant (response type = '{ this.FlowType }') supported";
        public override string Description => $"This test determines whether the server supports the hybrid grant (with response type '{ this.FlowType }').";
    }
    public abstract class HybridFlowSupportedTestImplementation : AuthorizationCodeFlowSupportedTestImplementation {
        public HybridFlowSupportedTestImplementation(string responseType, TestRunContext context, FlowSupportedTestResult result)
            : base($"Hybrid grant (response type = '{ responseType }')",
                  responseType, context, result) { }
    }
    public abstract class AuthorizationCodeFlowSupportedTestImplementation : FlowSupportedTestImplementation {
        public AuthorizationCodeFlowSupportedTestImplementation(string name, string responseType, TestRunContext context, FlowSupportedTestResult result)
            : base(name, responseType, context, result) { }
        protected override TokenProvider CreateProvider(TokenProviderSettings ps, TestRunContext tc) {
            return new AuthorizationCodeTokenProvider(ps, tc);
        }
    }

    ////////////////
    ///  CODE
    ////////////////
    public class CodeFlowSupportedTest : FlowSupportedTest {
        public CodeFlowSupportedTest() : base(OAuthHelper.CODE_FLOW_TYPE, typeof(CodeFlowSupportedTestResult)) { }
        public override string Title => $"Is the authorization code grant supported";
        public override string Description => $"This test determines whether the server supports the authorization code grant.";
    }
    public class CodeFlowSupportedTestResult : FlowSupportedTestResult {
        public CodeFlowSupportedTestResult(string testId) : base(testId, typeof(CodeFlowSupportedTestImplementation)) { }
    }
    public class CodeFlowSupportedTestImplementation : AuthorizationCodeFlowSupportedTestImplementation {
        public CodeFlowSupportedTestImplementation(TestRunContext context, CodeFlowSupportedTestResult result) 
            : base("Authorization Code grant", OAuthHelper.CODE_FLOW_TYPE, context, result) { 
        
        }
        protected override TokenProvider CreateProvider(TokenProviderSettings providerSettings, TestRunContext context) {
            var customContext = context with {
                SiteSettings = context.SiteSettings with { 
                     PKCEDefault = CurrentType
                }
            };
            return new AuthorizationCodeTokenProvider(providerSettings, customContext);
        }

        private PKCESupportTypes CurrentType { get; set; }

        public override async Task Run() {
            // try the 3 PKCE types
            var types = new PKCESupportTypes[] { PKCESupportTypes.Hash, PKCESupportTypes.Plain, PKCESupportTypes.None };
            var supportedTypes = Context.State.Get<List<PKCESupportTypes>>(StateKeys.WorkingPkceTypes);
            foreach (var type in types) {
                LogInfo($"Now testing the authorization code grant with PKCE type '{ type }'");
                this.CurrentType = type;
                await base.Run();
                if (Result.Outcome == TestOutcomes.SpecificationFullyImplemented) {
                    LogInfo($"The authorization code grant with PKCE type '{ type }' returns a valid token");
                    supportedTypes.Add(type);
                } else {
                    LogInfo($"The authorization code grant with PKCE type '{ type }' does not work");
                }
            }
            Result.Outcome = supportedTypes.Count > 0 ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
            await Context.Browser.SendFeatureDetected(OAuthHelper.CODE_FLOW_TYPE, Result.Outcome == TestOutcomes.SpecificationFullyImplemented);
        }
    }

    ////////////////
    ///  CODE TOKEN
    ////////////////
    public class CodeTokenFlowSupportedTest : HybridCodeFlowSupportedTest {
        public CodeTokenFlowSupportedTest() : base(OAuthHelper.CODE_TOKEN_FLOW_TYPE, typeof(CodeTokenFlowSupportedTestResult)) { }
    }
    public class CodeTokenFlowSupportedTestResult : FlowSupportedTestResult {
        public CodeTokenFlowSupportedTestResult(string testId) : base(testId, typeof(CodeTokenFlowSupportedTestImplementation)) { }
    }
    public class CodeTokenFlowSupportedTestImplementation : HybridFlowSupportedTestImplementation {
        public CodeTokenFlowSupportedTestImplementation(TestRunContext context, CodeTokenFlowSupportedTestResult result) : base(OAuthHelper.CODE_TOKEN_FLOW_TYPE, context, result) { }
    }

    ////////////////
    ///  CODE IDTOKEN
    ////////////////
    public class CodeIdTokenFlowSupportedTest : HybridCodeFlowSupportedTest {
        public CodeIdTokenFlowSupportedTest() : base(OAuthHelper.CODE_IDTOKEN_FLOW_TYPE, typeof(CodeIdTokenFlowSupportedTestResult)) { }
    }
    public class CodeIdTokenFlowSupportedTestResult : FlowSupportedTestResult {
        public CodeIdTokenFlowSupportedTestResult(string testId) : base(testId, typeof(CodeIdTokenFlowSupportedTestImplementation)) { }
    }
    public class CodeIdTokenFlowSupportedTestImplementation : HybridFlowSupportedTestImplementation {
        public CodeIdTokenFlowSupportedTestImplementation(TestRunContext context, CodeIdTokenFlowSupportedTestResult result) : base(OAuthHelper.CODE_IDTOKEN_FLOW_TYPE, context, result) { }
    }

    ////////////////
    ///  CODE IDTOKEN TOKEN
    ////////////////
    public class CodeIdTokenTokenFlowSupportedTest : HybridCodeFlowSupportedTest {
        public CodeIdTokenTokenFlowSupportedTest() : base(OAuthHelper.CODE_IDTOKEN_TOKEN_FLOW_TYPE, typeof(CodeIdTokenTokenFlowSupportedTestResult)) { }
    }
    public class CodeIdTokenTokenFlowSupportedTestResult : FlowSupportedTestResult {
        public CodeIdTokenTokenFlowSupportedTestResult(string testId) : base(testId, typeof(CodeIdTokenTokenFlowSupportedTestImplementation)) { }
    }
    public class CodeIdTokenTokenFlowSupportedTestImplementation : HybridFlowSupportedTestImplementation {
        public CodeIdTokenTokenFlowSupportedTestImplementation(TestRunContext context, CodeIdTokenTokenFlowSupportedTestResult result) : base(OAuthHelper.CODE_IDTOKEN_TOKEN_FLOW_TYPE, context, result) { }
    }
}