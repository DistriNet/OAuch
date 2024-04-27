using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.Pipeline {
    public class FinishAuthStage : Processor<ServerResponse, bool> {
        public override Task<bool> Process(ServerResponse value, IProvider tokenProvider, TokenResult tokenResult) {
            tokenResult.AuthorizationResponse = value;
            this.Succeeded = value.IsValid;
            return Task.FromResult(this.Succeeded);
        }
    }
}
