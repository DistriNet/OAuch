using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    //public abstract class Postprocessor<TIn, TOut> : Processor<TIn, TOut> {
    //    public Postprocessor(Processor<TIn, TOut> wrappedProcessor) {
    //        this.WrappedProcessor = wrappedProcessor;
    //        this.Succeeded = true;
    //    }
    //    public Processor<TIn, TOut> WrappedProcessor { get; }
    //    public abstract Task<TOut?> Postprocess(TOut? value);
    //    public async override Task<TOut?> Process(TIn value, TokenProvider tokenProvider, TokenResult tokenResult) {
    //        var result = await this.WrappedProcessor.Process(value, tokenProvider, tokenResult);
    //        this.Succeeded = this.WrappedProcessor.Succeeded;
    //        if (this.Succeeded) {
    //            return await Postprocess(result);
    //        }
    //        return default(TOut);
    //    }
    //}
}
