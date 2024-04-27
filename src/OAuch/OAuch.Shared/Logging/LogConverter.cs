namespace OAuch.Shared.Logging {
    public interface ILogConverter<TFrom> {
        public abstract LoggedItem Convert(TFrom item);
    }
}