using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public class MultiProcessor<TIn, TMiddle, TOut> : Processor<TIn, TOut> {
        public MultiProcessor(Processor<TIn, TMiddle> first, Processor<TMiddle, TOut> second ) {
            this.First = first;
            this.Second = second;
        }
        public Processor<TIn, TMiddle> First { get; }
        public Processor<TMiddle, TOut> Second { get; }

        public async override Task<TOut?> Process(TIn value, IProvider tokenProvider, TokenResult tokenResult) {
            var temp = await First.Process(value, tokenProvider, tokenResult);
            if (First.Succeeded) {
                var temp2 = await Second.Process(temp!, tokenProvider, tokenResult);
                this.Succeeded = Second.Succeeded;
                return temp2;
            }
            this.Succeeded = false;
            return default(TOut);
        }
    }
}
