using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DPoP {
    public class IsDPoPTokenRequiredTest : Test {
        public override string Title => "Does the test URI require DPoP tokens";

        public override string Description => "This test determines whether the test URI requires DPoP access tokens.";


        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;

        public override Type ResultType => typeof(IsDPoPTokenRequiredTestResult);
    }
    public class IsDPoPTokenRequiredTestResult : TestResult {
        public IsDPoPTokenRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsDPoPTokenRequiredTestImplementation);
    }
    public class IsDPoPTokenRequiredTestImplementation : TestImplementation {
        public IsDPoPTokenRequiredTestImplementation(TestRunContext context, IsDPoPTokenRequiredTestResult result, HasSupportedFlowsTestResult supportedFlows, TestUriSupportedTestResult test, IsDPoPSupportedTestResult dpop) : base(context, result, supportedFlows, dpop, test) { }
        public override async Task Run() {
            Result.Outcome = TestOutcomes.Skipped;

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) 
                return;            

            if (HasFailed<IsDPoPSupportedTestResult>() || HasFailed<TestUriSupportedTestResult>()) 
                return;
            
            var provider = flows.CreateProvider(Context, mustHaveDPoPTokens: true);
            if (provider == null) 
                return;            

            var token = await provider.GetToken();
            if (string.IsNullOrWhiteSpace(token.AccessToken))
                return; // weird

            var noDpopContext = Context with {
                SiteSettings = Context.SiteSettings with {
                    DPoPSigningKey = null
                }
            };

            var request = new ApiRequest(noDpopContext);
            var response = await request.Send(token);
            if (!response.StatusCode.IsOk()) { // the call to the API worked; now try the call again without an access token
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
