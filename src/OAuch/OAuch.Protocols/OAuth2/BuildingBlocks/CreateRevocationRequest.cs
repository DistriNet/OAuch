using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CreateRevocationRequest : CreateRequestBase {
        public CreateRevocationRequest(Action<IProvider, HttpRequest, Dictionary<string, string?>>? addClientAuthentication = null) 
            : base (ss => ss.RevocationUri!, addClientAuthentication) {}
    }
}
