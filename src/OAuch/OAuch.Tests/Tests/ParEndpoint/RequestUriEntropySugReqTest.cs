using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class RequestUriEntropySugReqTest : Test {
        public override string Title => "Are the PAR request uri's secure (160 bits)";
        public override string Description => "This test calculates the entropy of the PAR request uri's and verifies that they conform to the suggested requirements of 160 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RequestUriEntropySugReqTestResult);
    }
    public class RequestUriEntropySugReqTestResult : TestResult<EntropyInfo> {
        public RequestUriEntropySugReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RequestUriEntropySugReqTestImplementation);
        public override float? ImplementationScore {
            get {
                if (ExtraInfo?.AverageEntropy == null)
                    return base.ImplementationScore;
                return Math.Min((float)(ExtraInfo.AverageEntropy.Value / 160f), 1f);
            }
        }
    }
    public class RequestUriEntropySugReqTestImplementation : EntropyTestImplementationBase {
        public RequestUriEntropySugReqTestImplementation(TestRunContext context, RequestUriEntropySugReqTestResult result, RequestUriEntropyMinReqTestResult min, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, min, "PAR request_uri", 160, t => t.ParRequestUri, supportedFlows) { }
    }
}
