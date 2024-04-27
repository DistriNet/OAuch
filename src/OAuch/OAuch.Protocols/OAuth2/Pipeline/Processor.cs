using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public abstract class Processor { }
    public abstract class Processor<TIn, TOut> : Processor {
        public Processor() {
            this.Succeeded = true;
        }
        public abstract Task<TOut?> Process(TIn value, IProvider tokenProvider, TokenResult tokenResult);
        public virtual bool Succeeded { get; protected set; }

    }
}
