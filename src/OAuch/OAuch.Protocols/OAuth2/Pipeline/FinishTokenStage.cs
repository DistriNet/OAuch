using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public class FinishTokenStage : Processor<HttpServerResponse, bool> {
        public override Task<bool> Process(HttpServerResponse value, IProvider tokenProvider, TokenResult tokenResult) {
            tokenResult.TokenResponse = value;
            return Task.FromResult(value.IsValid);
        }
    }
}
