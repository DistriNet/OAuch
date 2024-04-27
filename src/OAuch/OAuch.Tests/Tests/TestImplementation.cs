using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Logging;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests {
    public abstract class TestImplementation {
        public TestImplementation(TestRunContext context, TestResult result, params TestResult[] dependencies) {
            this.Context = context;
            this.Http = new HttpHelper(context);
            this.Result = result;
            _dependencies = [.. dependencies];
        }

        protected TestRunContext Context { get; }
        protected HttpHelper Http { get; }
        protected TestResult Result { get; }
        protected void LogInfo(string message) => Context.Log.Log(message, LoggedStringTypes.Info);
        protected virtual void LogInfo(string info, string? expected, string? received) {
            expected ??= "(empty string)";
            received ??= "(empty string)";
            LogInfo($"{info} (expected '{expected}', received '{received}')");
        }
        protected void Log<T>(T o) where T : notnull => Context.Log.Log(o);

        public abstract Task Run();

        public T? GetDependency<T>(bool mustHaveSucceeded) where T : TestResult {
            if (_dependencies == null || _dependencies.Count == 0) {
                Debugger.Break();
                return null;
            }
            foreach (var t in _dependencies) {
                if (t is T tc) {
                    if (!mustHaveSucceeded || tc.Outcome == TestOutcomes.SpecificationFullyImplemented || tc.Outcome == TestOutcomes.SpecificationPartiallyImplemented)
                        return tc;
                    return null; // we found the dependency, but it failed
                }
            }
            Debugger.Break(); // the requested dependency was not in the list; this is a bug
            return null;
        }
        protected bool HasSucceeded<T>() where T : TestResult {
            return GetDependency<T>(true) != null;
        }
        protected bool HasFailed<T>() where T : TestResult {
            return !HasSucceeded<T>();
        }
        protected void AddDependency<T>(T dep) where T : TestResult {
            _dependencies.Add(dep);
        }
        private readonly List<TestResult> _dependencies;
    }
    public abstract class TestImplementation<T> : TestImplementation where T : new() {
        public TestImplementation(TestRunContext context, TestResult<T> result, params TestResult[] dependencies) : base(context, result, dependencies) {
            _typedResult = result;
        }
        public T ExtraInfo {
            get {
                T? ret = _typedResult.ExtraInfo;
                if (ret == null) {
                    ret = new T();
                    _typedResult.ExtraInfo = ret;
                }
                return ret;
            }
            set {
                _typedResult.ExtraInfo = value;
            }
        }
        private readonly TestResult<T> _typedResult;
    }
}
