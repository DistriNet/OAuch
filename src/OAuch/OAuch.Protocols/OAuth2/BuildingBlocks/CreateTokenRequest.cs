using OAuch.Protocols.Http;
using System;
using System.Collections.Generic;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CreateTokenRequest : CreateRequestBase {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0060:Remove unused parameter")]
        public CreateTokenRequest(Action<IProvider, HttpRequest, Dictionary<string, string?>>? addClientAuthentication = null)
            : base(ss => ss.TokenUri!) { }
    }
}
