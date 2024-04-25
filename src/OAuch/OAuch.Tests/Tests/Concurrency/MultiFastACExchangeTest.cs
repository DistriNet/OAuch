using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    public class MultiFastACExchangeTest : Test {
        public override string Title => "Can the authorization code be exchanged multiple times (multi server)?";
        public override string Description => "Can the authorization code be exchanged multiple times on different servers";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(MultiFastACExchangeTestResult);
    }
    public class MultiFastACExchangeTestResult : TestResult<ConcurrencyInfo> {
        public MultiFastACExchangeTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(MultiFastACExchangeTestImplementation);
    }
    public class MultiFastACExchangeTestImplementation : FastACExchangeTestImplementation {
        public MultiFastACExchangeTestImplementation(TestRunContext context, MultiFastACExchangeTestResult result, HasSupportedFlowsTestResult flows, MultipleCodeExchangesTestResult multi, SingleFastACExchangeTestResult singlefast, TestUriSupportedTestResult testUri) : base(context, result, flows, multi, testUri) {
            AddDependency(singlefast); 
        }
        public override Task Run() {
            //if (HasFailed<SingleFastACExchangeTestResult>()) {
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
        private const int SERVER_COUNT = 2;
    }
}