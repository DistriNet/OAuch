using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class RequestUriEntropyMinReqTest : Test {
        public override string Title => "Are the PAR request uri's secure (128 bits)";
        public override string Description => "This test calculates the entropy of the PAR request uri's and verifies that they conform to the minimum requirements of 128 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RequestUriEntropyMinReqTestResult);
    }
    public class RequestUriEntropyMinReqTestResult : TestResult<EntropyInfo> {
        public RequestUriEntropyMinReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RequestUriEntropyMinReqTestImplementation);
        public override float? ImplementationScore {
            get {
                if (ExtraInfo?.AverageEntropy == null)
                    return base.ImplementationScore;
                return Math.Min((float)(ExtraInfo.AverageEntropy.Value / 128f), 1f);
            }
        }
    }
    public class RequestUriEntropyMinReqTestImplementation : EntropyTestImplementationBase {
        public RequestUriEntropyMinReqTestImplementation(TestRunContext context, RequestUriEntropyMinReqTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, null, "PAR request_uri", 128, t => t.ParRequestUri, supportedFlows) { }
    }
}
