﻿using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;

namespace OAuch.Protocols.OAuth2 {
    public class PasswordTokenProvider : TokenProvider {
        public PasswordTokenProvider(TokenProviderSettings settings, TestRunContext context) : base(settings, context) { }
        protected override PipelineStage<bool> CreateTokenPipeline() {
            return ProviderPipeline.Start()
                .Then(new CheckTokenUri())
                .Then(new GetClaimParameters())
                .Then(new AddScope())
                .Then(new AddUsernamePassword())
                .Then(new CreateTokenRequest())
                .Then(new AddDPoPHeader())
                .Then(new SendRequest(UriTypes.TokenUri))
                .Then(new GetServerResponseFromHttpResponse())
                .FinishTokenResponse();
        }
    }
}
