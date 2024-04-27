using OAuch.Protocols.Http;
using System;
using System.Collections.Generic;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CreateRevocationRequest : CreateRequestBase {
        public CreateRevocationRequest(Action<IProvider, HttpRequest, Dictionary<string, string?>>? addClientAuthentication = null)
            : base(ss => ss.RevocationUri!, addClientAuthentication) { }
    }
}
