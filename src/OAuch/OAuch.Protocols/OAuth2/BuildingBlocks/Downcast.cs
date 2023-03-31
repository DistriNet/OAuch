using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class Downcast<T, TBase> : Processor<T, TBase> where T : TBase{
        public override Task<TBase?> Process(T value, IProvider tokenProvider, TokenResult tokenResult) {
            return Task.FromResult<TBase?>(value);
        }
    }

}
