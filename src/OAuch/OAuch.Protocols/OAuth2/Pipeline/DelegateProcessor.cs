using System;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public class DelegateProcessor<TIn, TOut> : Processor<TIn, TOut> {
        public DelegateProcessor(Func<TIn, TOut> converter) {
            this.Converter = converter;
        }
        public Func<TIn, TOut> Converter { get; }

        public override Task<TOut?> Process(TIn value, IProvider tokenProvider, TokenResult tokenResult) {
            try {
                this.Succeeded = true;
                return Task.FromResult<TOut?>(Converter.Invoke(value));
            } catch {
                this.Succeeded = false;
                return Task.FromResult(default(TOut));
            }
        }
    }
}
