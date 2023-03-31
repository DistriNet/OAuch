using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2 {
    public class DeviceTokenProvider : TokenProvider {
        public DeviceTokenProvider(TokenProviderSettings settings, TestRunContext context) : base(settings, context) { }

        protected override PipelineStage<bool> CreateTokenPipeline() {
            return ProviderPipeline.Start()
                .Then(new CheckDeviceAuthorizationUri())
                .Then(new CheckTokenUri())
                .Then(new GetDeviceCodeParameters())
                .Then(new AddScope())
                .Then(new CreateDeviceCodeRequest())
                .Then(new SendRequest(UriTypes.DeviceAuthorizationUri))
                .Then(new GetServerResponseFromHttpResponse())
                .Then(new Downcast<HttpServerResponse, ServerResponse>())
                .FinishAuthorizationResponse()
                .Then(new NotifyUser())
                .Then(new GetClaimParameters())
                .Then(new CreateTokenRequest())
                .Then(new PollForToken())
                .FinishTokenResponse();
        }
    }
}
