using System.Threading.Tasks;

namespace OAuch.Shared.Interfaces {
    public interface IBrowser {
        Task<ICallbackResult?> RequestCallback(string redirectUri);
        TaskCompletionSource<ICallbackResult?> RegisterCompletionSource();
        void RemoveCompletionSource(TaskCompletionSource<ICallbackResult?> c);
        Task RedirectPopup(string redirectUri, bool cancelable);
        Task SendMessage(string message);
        Task SendFeatureDetected(string id, bool present);
    }
    public interface ICallbackResult {
        string Url { get; }
        string FormData { get; }
    }
}
