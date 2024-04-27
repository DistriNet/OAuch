using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public class FinishStage<TFrom> : Processor<TFrom, bool> {
        public override Task<bool> Process(TFrom value, IProvider tokenProvider, TokenResult tokenResult) => Task.FromResult(true);
    }
}
