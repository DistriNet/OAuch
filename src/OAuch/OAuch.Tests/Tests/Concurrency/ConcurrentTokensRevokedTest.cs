using AngleSharp.Dom;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Shared.Enumerations;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.OAuth2;
using static System.Reflection.Metadata.BlobBuilder;

namespace OAuch.Compliance.Tests.Concurrency {
    public class ConcurrentTokensRevokedTest : Test {
        public override string Title => "Are concurrent tokens correctly revoked?";
        public override string Description => "Are the access and refresh tokens that were acquired through a race condition correctly revoked after disabling the client id";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(ConcurrentTokensRevokedTestResult);
    }
    public class ConcurrentTokensRevokedTestResult : TestResult<ConcurrentTokensInfo> {
        public ConcurrentTokensRevokedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(ConcurrentTokensRevokedTestImplementation);
    }
    public class ConcurrentTokensInfo : ITimeDelayedTest {
        public List<string>? AccessTokens { get; set; }
        public List<string>? RefreshTokens { get; set; }
        public DateTime? ResumeWhen { get; set; }
    }
    public class ConcurrentTokensRevokedTestImplementation : TestImplementation<ConcurrentTokensInfo> {
        public ConcurrentTokensRevokedTestImplementation(TestRunContext context, ConcurrentTokensRevokedTestResult result, HasSupportedFlowsTestResult flows, TestUriSupportedTestResult testUri, SingleFastACExchangeTestResult sfac, MultiFastACExchangeTestResult mfac, SingleFastRefreshTestResult sfr, MultiFastRefreshTestResult mfr) : base(context, result, flows, testUri, sfac, mfac, sfr, mfr) {
            //
        }
        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            // retrieve the tokens from the other tests
            var sfac = GetDependency<SingleFastACExchangeTestResult>(false);
            var mfac = GetDependency<MultiFastACExchangeTestResult>(false);
            var sfr = GetDependency<SingleFastRefreshTestResult>(false);
            var mfr = GetDependency<MultiFastRefreshTestResult>(false);
            ExtraInfo.AccessTokens = new List<string>();
            ExtraInfo.RefreshTokens = new List<string>();
            GetConcurrentTokens(ExtraInfo.AccessTokens, ExtraInfo.RefreshTokens, sfac, mfac, sfr, mfr);

            // if this is the first time we run this test...
            if (ExtraInfo.ResumeWhen == null) { 
                if (ExtraInfo.AccessTokens.Count == 0 && ExtraInfo.RefreshTokens.Count == 0) {
                    LogInfo("Could not find working access or refresh tokens that were acquired via a race condition.");
                    Result.Outcome = TestOutcomes.Skipped;
                } else {
                    ExtraInfo.ResumeWhen = DateTime.Now;
                    // keep Result.Outcome = null to make sure the test is resumed in a later test run
                    LogInfo($"OAuch has found {ExtraInfo.AccessTokens.Count} access tokens and {ExtraInfo.RefreshTokens.Count} refresh tokens that have been generated in race conditions.");
                    LogInfo("Please log in on the tested website as the test user and revoke the client app's authorization permissions. Once the client app has been removed from the user's profile, resume this test.");
                }
                return;
            }

            // the test has been resumed; the user access should have been revoked by now
            if (ExtraInfo.AccessTokens != null && ExtraInfo.AccessTokens.Count > 0) {
                var working = 0;
                foreach (var at in ExtraInfo.AccessTokens) {
                    if (await TokenTestHelper.TestAccessToken(Context, at)) {
                        LogInfo("Found working access token: " + at);
                        working++;
                    }
                }
                LogInfo($"{working} access tokens (out of a total of {ExtraInfo.AccessTokens.Count}) were still working");
                if (working > 0)
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
            if (ExtraInfo.RefreshTokens != null && ExtraInfo.RefreshTokens.Count > 0) {
                var provider = flows.CreateProvider(Context, true, false, false, true);
                if (provider == null) {
                    Result.Outcome = TestOutcomes.Skipped;
                    LogInfo("Could not find a working flow with refresh tokens");
                    return;
                }

                var working = 0;
                foreach (var rt in ExtraInfo.RefreshTokens) {
                    var (result, newRefresh) = await TokenTestHelper.TestRefreshToken(rt, provider);
                    if (result) {
                        LogInfo("Found working refresh token: " + rt);
                        working++;
                    }
                }
                LogInfo($"{working} refresh tokens (out of a total of {ExtraInfo.RefreshTokens.Count}) were still working");
                if (working > 0)
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }

            if (Result.Outcome == null) {
                // all tokens have been revoked correctly
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
        private void GetConcurrentTokens(List<string> accessTokens, List<string> refreshTokens, params TestResult<ConcurrencyInfo>?[] results) {
            foreach(var result in results) {
                if (result != null) {
                    if (result.ExtraInfo?.WorkingAccessTokens != null && result.ExtraInfo.WorkingAccessTokens.Count > 1) {
                        accessTokens.AddRange(result.ExtraInfo.WorkingAccessTokens);
                    }
                    if (result.ExtraInfo?.WorkingRefreshTokens != null && result.ExtraInfo.WorkingRefreshTokens.Count > 1) {
                        refreshTokens.AddRange(result.ExtraInfo.WorkingRefreshTokens);
                    }
                }
            }
        }
    }
}