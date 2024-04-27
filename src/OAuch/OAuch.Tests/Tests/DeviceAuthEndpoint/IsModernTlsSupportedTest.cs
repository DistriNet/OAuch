﻿using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.DeviceAuthEndpoint {
    public class IsModernTlsSupportedTest : Test {
        public override string Title => "Does the device authorization server support a modern version of TLS";
        public override string Description => "This test determines whether the device authorization server supports modern versions of the TLS protocol (v1.2 and higher).";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsModernTlsSupportedTestResult);
    }
    public class IsModernTlsSupportedTestResult : TestResult<IsModernTlsSupportedExtraInfo> {
        public IsModernTlsSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsModernTlsSupportedTestImplementation);
    }
    public class IsModernTlsSupportedTestImplementation : IsModernTlsSupportedTestImplementationBase {
        public IsModernTlsSupportedTestImplementation(TestRunContext context, IsModernTlsSupportedTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, context.SiteSettings.DeviceAuthorizationUri, supportedFlows) { }
    }

}
