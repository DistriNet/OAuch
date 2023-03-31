using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CreateDeviceCodeRequest : CreateRequestBase {
        public CreateDeviceCodeRequest() 
            : base(ss => ss.DeviceAuthorizationUri!) { }
    }
}
