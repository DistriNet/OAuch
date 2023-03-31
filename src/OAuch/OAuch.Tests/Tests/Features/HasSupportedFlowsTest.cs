using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class HasSupportedFlowsTest : Test {
        public override string Title => "Is at least one grant type supported";

        public override string Description => "This test determines whether at least one grant type is supported by the authorization server.";

        public override string? TestingStrategy => null;

        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;

        public override Type ResultType => typeof(HasSupportedFlowsTestResult);
    }
    public class HasSupportedFlowsTestResult : TestResult<HasSupportedFlowsTestInfo> {
        public HasSupportedFlowsTestResult(string testId) : base(testId) {}
        public override Type ImplementationType => typeof(HasSupportedFlowsTestImplementation);

        private void InitializeFactories() {
            if (_factories != null)
                return;
            
            _factories = new List<TokenProviderFactory>();
            if (this.ExtraInfo != null && this.ExtraInfo.WorkingProviders != null) {
                foreach (var providerInfo in this.ExtraInfo.WorkingProviders) {
                    _factories.Add(new TokenProviderFactory(providerInfo));
                }
            }
        }
        private List<TokenProviderFactory> _factories;

        public bool HasAccessTokens {
            get {
                InitializeFactories();
                return _factories.Any(c => c.HasAccessTokens);
            }
        }

        public bool HasJwtAccessTokens {
            get {
                InitializeFactories();
                return _factories.Any(c => c.HasJwtAccessTokens);
            }
        }

        public bool HasIdentityTokens {
            get {
                InitializeFactories();
                return _factories.Any(c => c.HasIdentityTokens);
            }
        }

        public bool HasAuthorizationCodes {
            get {
                InitializeFactories();
                return _factories.Any(c => c.HasAuthorizationCodes);
            }
        }

        public bool HasRefreshTokens {
            get {
                InitializeFactories();
                return _factories.Any(c => c.HasRefreshTokens);
            }
        }

        public bool HasFlow(string flowType) {
            InitializeFactories();
            foreach (var fact in _factories) {
                if (fact.FlowType == flowType)
                    return true;
            }
            return false;
        }

        public TokenProvider CreateAccessTokenProvider(TestRunContext context) => CreateProvider(context, false, false, false, false);
        public TokenProvider CreateIdentityTokenProvider(TestRunContext context) => CreateProvider(context, false, false, true, false, false);
        public TokenProvider CreateProvider(TestRunContext context, bool mustHaveRefresh, bool mustHaveJwtTokens, bool mustHaveIdTokens, bool mustHaveCodes, bool mustHaveAccessTokens = true) {
            InitializeFactories();
            foreach (var provider in _factories) {
                if ((!mustHaveAccessTokens || provider.HasAccessTokens) && (!mustHaveRefresh || provider.HasRefreshTokens) && (!mustHaveJwtTokens || provider.HasJwtAccessTokens) && (!mustHaveIdTokens || provider.HasIdentityTokens) && (!mustHaveCodes || provider.HasAuthorizationCodes))
                    return provider.CreateProvider(context);
            }
            throw new NotSupportedException();
        }
        public TokenProvider? CreateProvider(TestRunContext context, Func<TokenProviderFactory, TokenProvider, bool> validator, bool mustHaveAccessTokens = true, bool mustHaveRefresh = false, bool mustHaveJwtTokens = false, bool mustHaveIdTokens = false, bool mustHaveCodes = false) {
            InitializeFactories();
            foreach (var factory in _factories) {
                if ((!mustHaveAccessTokens || factory.HasAccessTokens) && (!mustHaveRefresh || factory.HasRefreshTokens) && (!mustHaveJwtTokens || factory.HasJwtAccessTokens) && (!mustHaveIdTokens || factory.HasIdentityTokens) && (!mustHaveCodes || factory.HasAuthorizationCodes)) {
                    var provider = factory.CreateProvider(context);
                    if (validator(factory, provider))
                        return provider;
                }
            }
            return null;
        }
        public TokenProvider? CreateProviderWithStage<TProcessor, TIn, TOut>(TestRunContext context, Func<TokenProviderFactory, TokenProvider, bool>? extraValidator = null, bool mustHaveAccessTokens = true, bool mustHaveRefresh = false, bool mustHaveJwtTokens = false, bool mustHaveIdTokens = false, bool mustHaveCodes = false) where TProcessor : Processor<TIn, TOut> {
            return CreateProvider(context, 
                (f, p) => p.Pipeline.HasProcessor<TProcessor>() && (extraValidator == null || extraValidator(f, p)),
                mustHaveAccessTokens, mustHaveRefresh, mustHaveJwtTokens, mustHaveIdTokens, mustHaveCodes);
        }
        public IList<TokenProviderFactory> GetFactories(bool mustHaveRefresh = false, bool mustHaveJwtTokens = false, bool mustHaveIdTokens = false, bool mustHaveCodes = false, bool mustHaveAccessTokens = true) {
            InitializeFactories();
            var ret = new List<TokenProviderFactory>();
            foreach (var provider in _factories) {
                if ((!mustHaveAccessTokens || provider.HasAccessTokens) && (!mustHaveRefresh || provider.HasRefreshTokens) && (!mustHaveJwtTokens || provider.HasJwtAccessTokens) && (!mustHaveIdTokens || provider.HasIdentityTokens) && (!mustHaveCodes || provider.HasAuthorizationCodes))
                    ret.Add(provider);
            }
            return ret;
        }
    }
    public class HasSupportedFlowsTestInfo { 
        public List<TokenProviderInfo>? WorkingProviders { get; set; }
    }
    public class HasSupportedFlowsTestImplementation : TestImplementation<HasSupportedFlowsTestInfo> {
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public HasSupportedFlowsTestImplementation(TestRunContext context, HasSupportedFlowsTestResult result, TokenFlowSupportedTestResult tokenFlow, IdTokenTokenFlowSupportedTestResult tokenIdTokenFlow, IdTokenFlowSupportedTestResult idTokenFlow, CodeFlowSupportedTestResult code, CodeTokenFlowSupportedTestResult codeToken, CodeIdTokenFlowSupportedTestResult codeIdToken, CodeIdTokenTokenFlowSupportedTestResult codeIdTokenToken, ClientCredentialsFlowSupportedTestResult clientCredentials, PasswordFlowSupportedTestResult password, DeviceFlowSupportedTestResult device) : base(context, result, tokenFlow, tokenIdTokenFlow, idTokenFlow, code, codeToken, codeIdToken, codeIdTokenToken, clientCredentials, password, device) { }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public override Task Run() {
            var allProviderResults = new TestResult<TokenProviderInfo>?[] {
                GetDependency<TokenFlowSupportedTestResult>(true),              // token
                GetDependency<IdTokenTokenFlowSupportedTestResult>(true),       // token id_token
                GetDependency<IdTokenFlowSupportedTestResult>(true),            // id_token
                GetDependency<CodeFlowSupportedTestResult>(true),               // code
                GetDependency<CodeTokenFlowSupportedTestResult>(true),          // code token
                GetDependency<CodeIdTokenFlowSupportedTestResult>(true),        // code id_token
                GetDependency<CodeIdTokenTokenFlowSupportedTestResult>(true),   // code id_token token
                GetDependency<ClientCredentialsFlowSupportedTestResult>(true),  // client_credentials
                GetDependency<PasswordFlowSupportedTestResult>(true),           // password
                GetDependency<DeviceFlowSupportedTestResult>(true)              // urn:ietf:params:oauth:grant-type:device_code
            };
            var workingProviders = new List<TestResult<TokenProviderInfo>>();
            foreach (var providerResult in allProviderResults) {
                if (providerResult != null && providerResult.Outcome == TestOutcomes.SpecificationFullyImplemented && providerResult.ExtraInfo?.Settings != null) {
                    workingProviders.Add(providerResult);
                }
            }
            ExtraInfo.WorkingProviders = workingProviders.Where(c => c.ExtraInfo != null).Select(c => c.ExtraInfo!).ToList();
            Result.Outcome = workingProviders.Count > 0 ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;

            foreach (var providerInfo in workingProviders) {
                LogInfo($"The { providerInfo.ExtraInfo!.Settings!.Name } is working ({ FormatFlow(providerInfo.ExtraInfo!) })");
            }

            Context.Browser.SendFeatureDetected("at", workingProviders.Any(wp => wp.ExtraInfo!.HasAccessTokens));
            Context.Browser.SendFeatureDetected("rt", workingProviders.Any(wp => wp.ExtraInfo!.HasRefreshTokens));
            Context.Browser.SendFeatureDetected("jwt", workingProviders.Any(wp => wp.ExtraInfo!.HasJwtAccessTokens));
            Context.Browser.SendFeatureDetected("id", workingProviders.Any(wp => wp.ExtraInfo!.HasIdentityTokens));

            return Task.CompletedTask;

            string FormatFlow(TokenProviderInfo flow) {
                var sb = new StringBuilder();
                if (flow.HasAccessTokens) {
                    if (flow.HasJwtAccessTokens) {
                        sb.Append("JWT ");
                    }
                    sb.Append("access tokens");
                }
                if (flow.HasIdentityTokens) {
                    if (sb.Length > 0)
                        sb.Append("; ");
                    sb.Append("identity tokens");
                }
                if (flow.HasRefreshTokens) {
                    if (sb.Length > 0)
                        sb.Append("; ");
                    sb.Append("refresh tokens");
                }
                return sb.ToString();
            }
        }
    }
}