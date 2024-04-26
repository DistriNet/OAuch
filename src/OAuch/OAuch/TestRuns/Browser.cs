using OAuch.Hubs;
using OAuch.LogConverters;
using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Interfaces;
using OAuch.Shared.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.TestRuns {
    public class Browser : IBrowser {
        public Browser(LogContext logger, TestRunConnection connection, StateCollection state) {
            _waitingCallbacks = [];
            this.Logger = logger;
            this.Connection = connection;
            this.State = state;
        }

        private TestRunConnection Connection { get; }
        public Task RedirectPopup(string redirectUri, bool cancelable) {
            return Connection.RedirectPopup(redirectUri, cancelable);
        }

        public Task<ICallbackResult?> RequestCallback(string redirectUri) {
            Logger.Log(new RedirectConverter.RedirectInfo { Url = redirectUri });

            var tcs = new TaskCompletionSource<ICallbackResult?>();
            lock (_waitingCallbacks) {
                _waitingCallbacks.Add(new CallbackInfo(redirectUri, tcs));
            }
            Connection.EnableCancel().ContinueWith(t => Connection.RedirectPopup(redirectUri, true));
            return tcs.Task;
        }
        // this is used when a test is running that is cancelable, but isn't waiting for a browser callback (e.g. when polling for the device flow)
        public TaskCompletionSource<ICallbackResult?> RegisterCompletionSource() {
            var tcs = new TaskCompletionSource<ICallbackResult?>();
            lock (_waitingCallbacks) {
                _waitingCallbacks.Add(new CallbackInfo(null, tcs));
            }
            return tcs;
        }

        public Task SendMessage(string message) {
            return Connection.SendMessage(message);
        }

        public LogContext Logger { get; }
        public StateCollection State { get; }

        public string? CurrentCallback {
            get {
                lock (_waitingCallbacks) {
                    if (_waitingCallbacks.Count == 0)
                        return null; // no callbacks
                    return _waitingCallbacks[^1].RedirectUri;
                }
            }
        }

        public void ProcessCallback(string href, string form) {
            TaskCompletionSource<ICallbackResult?> tcs;
            lock (_waitingCallbacks) {
                if (_waitingCallbacks.Count == 0)
                    return; // weird
                tcs = _waitingCallbacks[_waitingCallbacks.Count - 1].CompletionSource;
                _waitingCallbacks.RemoveAt(_waitingCallbacks.Count - 1);
            }
            var pars = new CallbackResult(href, form);
            Logger.Log(pars);
            tcs.SetResult(pars);
        }
        public void CancelCallback() {
            TaskCompletionSource<ICallbackResult?> tcs;
            lock (_waitingCallbacks) {
                if (_waitingCallbacks.Count == 0)
                    return; // user pressed cancel, but no test was waiting on a callback
                tcs = _waitingCallbacks[_waitingCallbacks.Count - 1].CompletionSource;
                _waitingCallbacks.RemoveAt(_waitingCallbacks.Count - 1);
            }
            Logger.Log("User clicked the 'stalled test' button", LoggedStringTypes.Info);
            tcs.SetResult(null);
        }
        public void RemoveCompletionSource(TaskCompletionSource<ICallbackResult?> c) {
            TaskCompletionSource<ICallbackResult?> tcs;
            lock (_waitingCallbacks) {
                if (_waitingCallbacks.Count == 0)
                    return; // already canceled?
                tcs = _waitingCallbacks[_waitingCallbacks.Count - 1].CompletionSource;
                if (tcs == c)
                    _waitingCallbacks.RemoveAt(_waitingCallbacks.Count - 1);
            }
            if (tcs == c) {
                Logger.Log("User clicked the 'stalled test' button", LoggedStringTypes.Info);
                tcs.SetResult(null);
            }
        }

        public async Task SendFeatureDetected(string name, bool available) {
            var list = this.State.Get<Dictionary<string, bool>>(StateKeys.FeatureCache);
            list[name] = available;
            await Connection.SendFeatureDetected(name, available);
        }
        public async Task SendFeatureDetected(string connectionId, string name, bool available) {
            await Connection.SendFeatureDetected(connectionId, name, available);
        }

        private readonly List<CallbackInfo> _waitingCallbacks;

        private class CallbackInfo {
            public CallbackInfo(string? redirectUri, TaskCompletionSource<ICallbackResult?> completionSource) {
                this.RedirectUri = redirectUri;
                this.CompletionSource = completionSource;
            }
            public string? RedirectUri { get; }
            public TaskCompletionSource<ICallbackResult?> CompletionSource { get; }
        }
    }
}
