using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    public class SingleFastACExchangeTest : Test {
        public override string Title => "Can the authorization code be exchanged multiple times (single server)?";
        public override string Description => "Can the authorization code be exchanged multiple times on the same server";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(SingleFastACExchangeTestResult);
    }
    public class SingleFastACExchangeTestResult : TestResult<ConcurrencyInfo> {
        public SingleFastACExchangeTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(SingleFastACExchangeTestImplementation);
    }
    public class SingleFastACExchangeTestImplementation : FastACExchangeTestImplementation {
        public SingleFastACExchangeTestImplementation(TestRunContext context, SingleFastACExchangeTestResult result, HasSupportedFlowsTestResult flows, MultipleCodeExchangesTestResult multi, TestUriSupportedTestResult testUri) : base(context, result, flows, multi, testUri) { }
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
