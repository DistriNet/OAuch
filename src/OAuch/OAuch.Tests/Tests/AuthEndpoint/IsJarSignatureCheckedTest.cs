using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.ParEndpoint;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class IsJarSignatureCheckedTest : Test {
        public override string Title => "Is the JAR signature checked";
        public override string Description => "This test checks whether the signature on the JWT in the request_uri parameter is checked for validity.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsJarSignatureCheckedTestResult);
    }
    public class IsJarSignatureCheckedTestResult : TestResult {
        public IsJarSignatureCheckedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsJarSignatureCheckedTestImplementation);
    }
    public class IsJarSignatureCheckedTestImplementation : TestImplementation {
        public IsJarSignatureCheckedTestImplementation(TestRunContext context, IsJarSignatureCheckedTestResult result, HasSupportedFlowsTestResult flows, IsJarSupportedTestResult jar) : base(context, result, flows, jar) { }

        public async override Task Run() {
            if (HasFailed<IsJarSupportedTestResult>() ||  // no JAR support
                Context.SiteSettings.RequestSigningKey == null) { // no signing key
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var prov = flows.CreateProviderWithStage<RewriteAsJwt, Dictionary<string, string?>, Dictionary<string, string?>>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the JAR standard (weird, should not happen here, because we know JAR is supported)
                return;
            }
            prov.Pipeline.Replace<RewriteAsJwt, Dictionary<string, string?>, Dictionary<string, string?>>(new ModifyJarSignature());

            var result = await prov.GetToken();
            if (result.AccessToken == null && result.IdentityToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server detected the invalid signature.");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server issued a valid token despite an invalid signature.");
            }
        }
        class ModifyJarSignature : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
                var settings = provider.SiteSettings with {
                    UseRequestParameter = true
                };
                OAuthHelper.RewriteAsJwt(provider.SiteSettings, value);

                // re-sign the token with a different (dummy) key
                var dummyKey = JsonWebKey.Create("""
                {
                    "p": "3Um8kbDzpLPghGY3RBOn8DYSG1xqzqSNG2KeVRYJD7IfE7JDNh71q7QECmV1J2RGkXE5jyrCs4X7PBu_R2Vy8g3WtqWBsCVN82pz8eolL1nFw0PpVovgOdM8jSuiwMBklJbBhUaAj25Ejwr9tP7BfBIdMebUwYNy694LLjxwKI8",
                    "kty": "RSA",
                    "q": "piQL6vpW_MZMqeRXAdqiugplBBPzdi02CG939dyaXeZR7pnME0_XrFpRznHc9jaB9xvqP7hD7GtEr7m3IoAbzuJjuuEXTxDKJwjBvYqOod8nmJnII6ZCcQ5Ri0CnQJKk4d9WRR-juq67qxlb4-LORNvqSh8ZdoF7VOGoMaaycb8",
                    "d": "E8doueVSp3pGozViWuCAVNFLRUmKI0lGeHAQto2TS1qNYzADkdVeVtM4CwN09axx0hLGfZRdb3RnHKmfWrfoKzsNjcgMKAioZs9eby7m8NHWbe1NBuUiuv8qMqkB4pF9PInlLQVcm3QAdQKWmze73XyV4QIpIRp64iC9jpDMWZ1n6NxZxURm1TH-aoChb7mH-wjs1VDftLbrUTYKj6abxBaM1iSchxlBRsUpYvq-FnXp82XkzNaqEIIWrHE3ksvBPD7_XNcypEZzQKW07s0O1nerkoF65HnonvayqJNZYzveDIjIozrbd_1LFQs0YM9ZtFN_PTF4d9gJf_kM520TyQ",
                    "e": "AQAB",
                    "use": "sig",
                    "qi": "OBA2ztB1CcWHLnjq4qJLGejOpnIxwqNqQ1Q_66Bf2DEoA9PG2n0nVfwlC5zuRYNwg8PSchzftGgqa0vZxWr_YKNJsJNVV5rUf78EORKXe3mTBDK9L5pUSEhPZoIxj2pU0rdzQ0AzHgFC-FSkTbviyiKeTmI-hw0IhelDfH6Iqpk",
                    "dp": "Pl_veD2hn7ZYPdm2EEleGBaVqgK11IOLhsGYkbFBYpw5qEqiKVo2s2xtiySoDi90uMBqkhFiiknk1D-Z_hz5doMyF4-1a5pIS6mg_vqZ-qvaU70Lw6pvzLzfH4fCO4S_lSada9zAli1lw9A8TU1V6owMkKlZJSbROO0Ax8qfbr8",
                    "alg": "RS256",
                    "dq": "kbAYV1RxBTXqsiwOdAzCF3vX-wx3uNCKijkdK5boMqEuhZmOD_06teN5yxuj1LAVpZhwALJXtbCWybWENxe5yuBQ7eZGZ0nkyvft1IT08FNcSH_JtiEsMDGLJh5qy8AMIBmVcAX_sEtbO_1_y8TudgmWWKsOzBFdEiDTOb7gycc",
                    "n": "j5z48kYgskGiVRaQbeaQkp-gb1FFSOAADHAfC86WkxVoBru5fIm7tWThtyahBIVnJAmLuUnFdGUoIoJ30Bpm_Pi0aMKCISaHVK8WtKZ9zuXxIaFaXlabxUlhG7dLQxaDqNiC4_47IW2lm-j1cZK4uzSQ68ATJvWBaDF0jNu40mRfIeR4Z2WFcZPmGCgqmXVe4Vz4BZp7qSo1zmG7BxeypkqTXNWsWl_9IGLl8tYIFU8106UIikrygrJtAwJ32fd4C_ky1wyzhnKfgFckJ1RIN86dcfIR7xvyxsLz0JRB1lWRPzTsfbmcDFhofvKufmYEw4UBLSXMu5l8tRvUhwNhsQ"
                }
                """);

                var builder = JwtTokenBuilder.CreateFromToken(value["request"]);
                value["request"] = builder!.Build(dummyKey!.TokenKey);

                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
