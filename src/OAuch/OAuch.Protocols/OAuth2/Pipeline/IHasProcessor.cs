namespace OAuch.Protocols.OAuth2.Pipeline {
    public interface IHasProcessor {
        public Processor Processor { get; set; }
    }
}
