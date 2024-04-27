using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    public class SingleFastRefreshTest : Test {
        public override string Title => "Can the refresh token be exchanged multiple times (single server)?";
        public override string Description => "Can the refresh token be exchanged multiple times on the same server";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(SingleFastRefreshTestResult);
    }
    public class SingleFastRefreshTestResult : TestResult<ConcurrencyInfo> {
        public SingleFastRefreshTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(SingleFastRefreshTestImplementation);
    }
    public class SingleFastRefreshTestImplementation : FastRefreshTestImplementation {
        public SingleFastRefreshTestImplementation(TestRunContext context, SingleFastRefreshTestResult result, HasSupportedFlowsTestResult flows, TestUriSupportedTestResult testUri, RefreshTokenRevokedAfterUseTestResult refreshRevoked) : base(context, result, flows, testUri) {
            AddDependency(refreshRevoked);
        }
        public override Task Run() {
            var dep = GetDependency<RefreshTokenRevokedAfterUseTestResult>(false);
            if (dep?.Outcome == TestOutcomes.SpecificationNotImplemented) {
                LogInfo("Server uses token rotation, but allows refresh tokens to be reused anyway...");
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }
            return base.Run();
        }
        public override IReadOnlyList<ServerInfo>? ResolveAddresses() {
            var ip = MultiResolver.Resolve(Context.SiteSettings.TokenUri ?? "", 1);
            if (ip.Count == 0)
                return null;

            var ipList = new List<IPAddress>();
            for (int i = 0; i < SERVER_COUNT; i++) {
                ipList.Add(ip[0].Ip);
            }
            return ipList.Select(ip => new ServerInfo(ip)).ToList();
        }
        private const int SERVER_COUNT = 5;
    }
}
