using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared.Enumerations;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class AddPKCEChallenge : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public AddPKCEChallenge(PKCESupportTypes pkceUsage) {
            this.PKCEUsage = pkceUsage;
        }
        public PKCESupportTypes PKCEUsage { get; }
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            if (this.PKCEUsage != PKCESupportTypes.None) {
                if (tokenProvider is AuthorizationCodeTokenProvider acprov) {
                    if (this.PKCEUsage == PKCESupportTypes.Hash) {
                        value["code_challenge"] = OAuthHelper.S256(acprov.CodeVerifier);
                        value["code_challenge_method"] = "S256";
                    } else { // plain
                        value["code_challenge"] = acprov.CodeVerifier;
                        value["code_challenge_method"] = "plain";
                    }
                } // else: we tried adding PKCE support for non AC-flows
            }
            return Task.FromResult<Dictionary<string, string?>?>(value);
        }
    }
}
