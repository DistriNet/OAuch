using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public class PipelineStartStage<T> : PipelineStage<T> {
        public PipelineStartStage(T value) {
            this.Result = value;
            this.AllStages = new StageList(this);
        }

        internal override StageList AllStages { get; }

        public override Task<bool> Run(IProvider tokenProvider, TokenResult tokenResult) {
            return Task.FromResult(true);
        }
    }
}
