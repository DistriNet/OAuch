using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    public class MultiFastRefreshTest : Test {
        public override string Title => "Can the refresh token be exchanged multiple times (multi server)?";
        public override string Description => "Can the refresh token be exchanged multiple times on different servers";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(MultiFastRefreshTestResult);
    }
    public class MultiFastRefreshTestResult : TestResult<ConcurrencyInfo> {
        public MultiFastRefreshTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(MultiFastRefreshTestResultImplementation);
    }
    public class MultiFastRefreshTestResultImplementation : FastRefreshTestImplementation {
        public MultiFastRefreshTestResultImplementation(TestRunContext context, MultiFastRefreshTestResult result, HasSupportedFlowsTestResult flows, SingleFastRefreshTestResult singlefast, TestUriSupportedTestResult testUri) : base(context, result, flows, testUri) {
            AddDependency(singlefast);
        }
        public override Task Run() {
            //if (HasFailed<SingleFastRefreshTestResult>()) {
            //    Result.Outcome = TestOutcomes.Skipped;
            //    return Task.CompletedTask;
            //}
            return base.Run();
        }
        public override IReadOnlyList<ServerInfo>? ResolveAddresses() {
            var addresses = MultiResolver.Resolve(Context.SiteSettings.TokenUri ?? "", SERVER_COUNT).ToList();
            var distinct = addresses.Select(c => c.Ip).Distinct().Count();
            if (distinct == 1)
                return null;

            LogInfo($"Found {distinct} unique IP addresses for the token server.");
            return addresses;
        }
        private const int SERVER_COUNT = 25;
    }
}
