using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CreateTokenRequest : CreateRequestBase {
        public CreateTokenRequest(Action<IProvider, HttpRequest, Dictionary<string, string?>>? addClientAuthentication = null) 
            : base(ss => ss.TokenUri!) {}
    }
}
