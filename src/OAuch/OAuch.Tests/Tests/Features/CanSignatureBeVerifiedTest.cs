using OAuch.Protocols.Http;
using OAuch.Protocols.JWK;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class CanSignatureBeVerifiedTest : Test {
        public override string Title => "Can signatures be verified";
        public override string Description => "This test tries to download the key set from the JWKS URI. If the keyset cannot be downloaded, signatures on tokens cannot be verified.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(CanSignatureBeVerifiedTestResult);
    }
    public class CanSignatureBeVerifiedTestResult : TestResult {
        public CanSignatureBeVerifiedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(CanSignatureBeVerifiedTestImplementation);
    }
    public class CanSignatureBeVerifiedTestImplementation : TestImplementation {
        public CanSignatureBeVerifiedTestImplementation(TestRunContext context, CanSignatureBeVerifiedTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, supportedFlows) { }
        public override async Task Run() {
            var keyset = await LoadKeySet();
            Result.Outcome = keyset != null && keyset.Count > 0 ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
        }
        public async Task<JwkSet?> LoadKeySet() {
            var jwksUrl = Context.SiteSettings.JwksUri;
            if (string.IsNullOrWhiteSpace(jwksUrl))
                return null;

            // check if it's in the cache
            var store = Context.State.Find<JwkSet>(StateKeys.JsonWebKeySet);
            if (store != null)
                return store;

            // download the key store
            var request = HttpRequest.CreateGet(jwksUrl);
            var http = new HttpHelper(Context);
            var response = await http.SendRequest(request);
            if (response.StatusCode.IsOk()) {
                var json = response.ToString(true);
                var keyStore = JwkSet.Create(json, Context.Log);
                if (keyStore != null) {
                    Context.State.Add(StateKeys.JsonWebKeySet, keyStore);
                    return keyStore;
                }
            }
            return null;
        }
    }
}
