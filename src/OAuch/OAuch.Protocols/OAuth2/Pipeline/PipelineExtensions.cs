namespace OAuch.Protocols.OAuth2.Pipeline {
    public static class PipelineExtensions {
        public static PipelineStage<TNew> Then<TOrg, TNew>(this PipelineStage<TOrg> pipeline, Processor<TOrg, TNew> processor) {
            return new PipelineStage<TNew, TOrg>(pipeline, processor);
        }
        public static PipelineStage<bool> Finish<TOrg>(this PipelineStage<TOrg> pipeline) {
            return new PipelineStage<bool, TOrg>(pipeline, new FinishStage<TOrg>());
        }
        public static PipelineStage<bool> FinishAuthorizationResponse(this PipelineStage<ServerResponse> pipeline) {
            return new PipelineStage<bool, ServerResponse>(pipeline, new FinishAuthStage());
        }
        public static PipelineStage<bool> FinishTokenResponse(this PipelineStage<HttpServerResponse> pipeline) {
            return new PipelineStage<bool, HttpServerResponse>(pipeline, new FinishTokenStage());
        }
    }
}
