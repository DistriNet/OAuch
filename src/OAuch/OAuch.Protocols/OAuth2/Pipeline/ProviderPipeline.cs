namespace OAuch.Protocols.OAuth2.Pipeline {
    public static class ProviderPipeline {
        public static PipelineStage<T> FromStartValue<T>(T value) {
            return new PipelineStartStage<T>(value);
        }
        public static PipelineStage<bool> Start() {
            return new PipelineStartStage<bool>(true);
        }
        public static PipelineStage<T> Start<T>(T initialValue) {
            return new PipelineStartStage<T>(initialValue);
        }
    }
}
