using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Linq.Expressions;

namespace OAuch.Compliance.Tests.Concurrency {
    public abstract class FastACExchangeTestImplementation : ConcurrencyTestImplementation {
        public FastACExchangeTestImplementation(TestRunContext context, TestResult<ConcurrencyInfo> result, HasSupportedFlowsTestResult flows, MultipleCodeExchangesTestResult multi, TestUriSupportedTestResult testUri) : base(context, result, flows, testUri) {
            AddDependency(multi);
        }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<MultipleCodeExchangesTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            var provider = flows.CreateProvider(Context, false, false, false, true);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with authorization codes");
                return;
            }

            // get the authorization code using the AC flow
            var pipeline = ProviderPipeline.Start()
                .Then(new CheckAuthorizationUri())
                .Then(new CheckTokenUri())
                .Then(new GetAuthParameters())
                .Then(new AddScope())
                .Then(new AddPKCEChallenge(this.Context.SiteSettings.PKCEDefault))
                .Then(new AddResponseMode(ResponseModes.Query))
                .Then(new AddNonce())
                .Then(new RewriteAsJwt())
                .Then(new BuildAuthorizationUrl())
                .Then(new SendAuthorizationRedirect())
                .Then(new GetServerResponseFromCallback(ResponseModes.Query))
                .FinishAuthorizationResponse();
            var tokenResult = new TokenResult();
            await pipeline.Run(provider, tokenResult);

            if (tokenResult.AuthorizationResponse == null || tokenResult.AuthorizationResponse.Code == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not request an authorization code");
                return;
            }

            // run the test
            var baseToken = new TokenResult() { AuthorizationResponse = tokenResult.AuthorizationResponse };
            var requestPipeline = ProviderPipeline.Start()
                   .Then(new GetClaimParameters())
                   .Then(new AddRedirectUri())
                   .Then(new AddPKCEVerifier(this.Context.SiteSettings.PKCEDefault))
                   .Then(new CreateTokenRequest());
            await RunInternal(provider, baseToken, requestPipeline);
        }
    }
}
