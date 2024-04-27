﻿using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared.Enumerations;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class AddPKCEVerifier : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public AddPKCEVerifier(PKCESupportTypes pkceUsage) {
            this.PKCEUsage = pkceUsage;
        }
        public PKCESupportTypes PKCEUsage { get; }
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
            if (this.PKCEUsage != PKCESupportTypes.None) {
                if (tokenProvider is AuthorizationCodeTokenProvider acprov) {
                    value["code_verifier"] = acprov.CodeVerifier;
                } // else: we tried adding PKCE support for non AC-flows
            }
            return Task.FromResult<Dictionary<string, string?>?>(value);
        }
    }
}
