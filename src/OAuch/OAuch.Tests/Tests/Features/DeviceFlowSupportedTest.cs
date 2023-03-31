using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class DeviceFlowSupportedTest : FlowSupportedTest {
        public DeviceFlowSupportedTest() : base(OAuthHelper.DEVICE_FLOW_TYPE, typeof(DeviceFlowSupportedTestResult)) { }
        public override string Title => $"Is the device authorization grant supported";
        public override string Description => $"This test determines whether the server supports the device authorization grant.";
    }
    public class DeviceFlowSupportedTestResult : FlowSupportedTestResult {
        public DeviceFlowSupportedTestResult(string testId) : base(testId, typeof(DeviceFlowSupportedTestImplementation)) { }
    }
    public class DeviceFlowSupportedTestImplementation : FlowSupportedTestImplementation {
        public DeviceFlowSupportedTestImplementation(TestRunContext context, DeviceFlowSupportedTestResult result)
            : base("Device Authorization grant", OAuthHelper.DEVICE_FLOW_TYPE, context, result) { }
        protected override TokenProvider CreateProvider(TokenProviderSettings s, TestRunContext c) {
            return new DeviceTokenProvider(s, c);
        }
    }
}
