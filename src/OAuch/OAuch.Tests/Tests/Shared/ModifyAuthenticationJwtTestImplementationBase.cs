using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Jwt;
using OAuch.Protocols.Http;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public abstract class ModifyAuthenticationJwtTestImplementationBase : TestImplementation {
        public ModifyAuthenticationJwtTestImplementationBase(TestRunContext context, TestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) 
            : base(context, result, flows, jwt) {}


        protected virtual TokenKey Key {
            get {
                var settings = Context.SiteSettings;
                if (settings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.ClientSecretJwt && !string.IsNullOrEmpty(settings.DefaultClient.ClientSecret)) {
                    return TokenKey.FromBytes(Encoding.UTF8.GetBytes(settings.DefaultClient.ClientSecret));
                } else if (settings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt) {
                    var jwk = JsonWebKey.Create(settings.RequestSigningKey);
                    if (jwk != null) {
                        return jwk.TokenKey;
                    }
                }
                return TokenKey.Empty;
            }
        }
        protected virtual void ModifyToken(JwtTokenBuilder builder) { 
            // leave the token unmodified by default
        }
        protected virtual string BuildToken(JwtTokenBuilder builder) {
            return builder.Build(Key);
        }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<SupportsJwtClientAuthenticationTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var selectedType = Context.SiteSettings.ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt ? ClientAuthenticationMechanisms.PrivateKeyJwt : ClientAuthenticationMechanisms.ClientSecretJwt;
            var jwtContext = this.Context with
            {
                SiteSettings = this.Context.SiteSettings with
                {
                    ClientAuthenticationMechanism = selectedType
                }
            };
            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(jwtContext);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working provider that accesses the token endpoint");
                return;
            }

            var processor = provider.Pipeline.FindProcessor<CreateTokenRequest>();
            processor!.AddClientAuthenticationMethod = (tokenProvider, request, parameters) => {
                OAuthHelper.AddClientAuthentication(tokenProvider.SiteSettings, request.Headers, parameters);
                var builder = JwtTokenBuilder.CreateFromToken(parameters["client_assertion"]);
                ModifyToken(builder!);
                parameters["client_assertion"] = BuildToken(builder!);
            };

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                if (LogResult)
                    LogInfo("The server rejected the invalid client authentication JWT");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                if (LogResult)
                    LogInfo("The server did not reject the invalid client authentication JWT");
            }
        }
        protected virtual bool LogResult => true;
    }
}
