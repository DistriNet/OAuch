using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class GetServerResponseFromCallback : Processor<ICallbackResult?, ServerResponse> {
        public GetServerResponseFromCallback(ResponseModes defaultMode) {
            this.DefaultMode = defaultMode;
        }
        public ResponseModes DefaultMode { get; }

        public override Task<ServerResponse?> Process(ICallbackResult? callbackResult, IProvider tokenProvider, TokenResult tokenResult) {
            if (callbackResult == null)
                return Task.FromResult<ServerResponse?>(new ServerResponse { OriginalContents = callbackResult?.ToString(), UnexpectedError = new ArgumentException("The user clicked the 'stalled' button"), WasCallbackStalled = true });
            return Task.FromResult<ServerResponse?>(ServerResponse.FromCallbackResult(callbackResult, tokenProvider.SiteSettings.ResponseMode, this.DefaultMode, tokenProvider.Log));
        }
    }
}
