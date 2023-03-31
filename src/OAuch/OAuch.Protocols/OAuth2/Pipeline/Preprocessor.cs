using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    //public abstract class Preprocessor<TIn, TOut> : Processor<TIn, TOut> {
    //    public Preprocessor(Processor<TIn, TOut> wrappedProcessor) {
    //        this.WrappedProcessor = wrappedProcessor;
    //        this.Succeeded = true;
    //    }
    //    public Processor<TIn, TOut> WrappedProcessor { get; }
    //    public abstract Task<TIn> Preprocess(TIn value);
    //    public async override Task<TOut?> Process(TIn value, TokenProvider tokenProvider, TokenResult tokenResult) {
    //        var newValue = await Preprocess(value);
    //        if (this.Succeeded) {
    //            var result = await this.WrappedProcessor.Process(newValue, tokenProvider, tokenResult);
    //            this.Succeeded = this.WrappedProcessor.Succeeded;
    //            return result;
    //        }
    //        return default(TOut);
    //    }
    //}
}
