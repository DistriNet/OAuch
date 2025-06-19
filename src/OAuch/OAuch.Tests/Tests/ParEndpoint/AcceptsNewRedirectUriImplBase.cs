using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ParEndpoint {
    public abstract class AcceptsNewRedirectUriImplBase : TestImplementation<RedirectUriFullyMatchedTestInfo> {
        public AcceptsNewRedirectUriImplBase(TestRunContext context, TestResult<RedirectUriFullyMatchedTestInfo> result, params TestResult[] dependencies) : base(context, result, dependencies) {}

        public async Task Execute(SiteSettings settings) {
            if (HasFailed<IsParSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped; // no PAR support
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || string.IsNullOrEmpty(this.Context.SiteSettings.CallbackUri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            string callbackUriBase = new Uri(this.Context.SiteSettings.CallbackUri).GetLeftPart(UriPartial.Path);
            if (callbackUriBase.EndsWith('/'))
                callbackUriBase = callbackUriBase.TrimEnd('/');
            callbackUriBase += "/Modified";

            var modContext = this.Context with {
                SiteSettings = settings with {
                    CallbackUri = callbackUriBase
                }
            };
            var provider = flows.CreateProviderWithStage<SendAuthorizationRedirect, string, ICallbackResult?>(modContext);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var redirectResultProcessor = new RedirectPathResultProcessor(this.Context.SiteSettings.CallbackUri);
            provider.Pipeline.AddAfter<SendAuthorizationRedirect, string, ICallbackResult?>(redirectResultProcessor);

            var result = await provider.GetToken();
            ExtraInfo.WrongRedirect = redirectResultProcessor.WrongRedirect;
            if (redirectResultProcessor.WrongRedirect == null) {
                ExtraInfo.Result = RedirectUriMatchedResults.UserNotified;
            } else if (result.AccessToken == null) {
                LogInfo("The authorization server denied the request");
                ExtraInfo.Result = RedirectUriMatchedResults.RequestDenied;
            } else if (redirectResultProcessor.WrongRedirect == false) {
                LogInfo("The authorization server ignored the modified redirect URI");
                ExtraInfo.Result = RedirectUriMatchedResults.ParameterIgnored;
            } else {
                LogInfo("The authorization server used the modified redirect URI");
                //Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                ExtraInfo.Result = RedirectUriMatchedResults.RequestAllowed;
            }
        }

        class RedirectPathResultProcessor : Processor<ICallbackResult?, ICallbackResult?> {
            public RedirectPathResultProcessor(string originalCallback) {
                this.OriginalCallback = originalCallback;
            }
            public bool? WrongRedirect { get; private set; }
            public string OriginalCallback { get; private set; }
            public override Task<ICallbackResult?> Process(ICallbackResult? value, IProvider tokenProvider, TokenResult tokenResult) {
                this.WrongRedirect = null;
                if (value != null && Uri.TryCreate(this.OriginalCallback, UriKind.Absolute, out var settingsUri)) {
                    var uri = new Uri(value.Url);
                    this.WrongRedirect = Uri.Compare(uri, settingsUri, UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) != 0;
                }
                return Task.FromResult(value);
            }
        }
    }
}
