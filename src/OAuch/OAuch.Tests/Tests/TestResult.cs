using Newtonsoft.Json;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests {
    public abstract class TestResult {
        public TestResult(string testId) {
            this.TestId = testId;
            this.TestLog = new LoggedTest { TestId = testId };
        }
        [JsonProperty]
        public string TestId { get; private set; }
        [JsonProperty]
        public DateTime StartedAt { get; set; }
        [JsonProperty]
        public TestOutcomes? Outcome { get; set; }
        [JsonProperty]
        public LoggedTest TestLog { get; set; }

        [JsonIgnore]
        public virtual float? ImplementationScore {
            get {
                // This is the default implementation of the implementation score, which is valid for most test cases;
                // however, some test cases may return a number between [0..1] if the test case is not fully implemented,
                // but not completely unmitigated either (e.g., entropy of token is not 128 bit but 90 bit)
                if (this.Outcome == TestOutcomes.SpecificationNotImplemented)
                    return 0f;
                else if (this.Outcome == TestOutcomes.SpecificationFullyImplemented)
                    return 1f;
                Debug.Assert(this.Outcome != TestOutcomes.SpecificationPartiallyImplemented); // should not occur in test results?
                return null; // Failed, Skipped
            }
        }

        [JsonIgnore]
        public abstract Type ImplementationType { get; }
        [JsonIgnore]
        private ParameterInfo[] ConstructorParameters {
            get {
                if (_constructorParameters == null) {
                    var implementationType = ImplementationType;
                    //var contextType = typeof(TestRunContext);
                    //var testResultType = typeof(TestResult);
                    var consts = implementationType.GetConstructors();
                    if (consts.Length != 1) {
                        Debugger.Break(); // this should never happen!
                                          // when we get here, we have created multiple (or none) public constructors on
                                          // one of our implementation types
                        throw new MethodAccessException("Too many or not enough public constructors for type " + implementationType.FullName);
                    }
                    _constructorParameters = consts[0].GetParameters();
                }
                return _constructorParameters;
            }
        }
        private ParameterInfo[]? _constructorParameters;

        protected TestImplementation CreateImplementation(TestRunContext context, IList<TestResult> results) {
            var implementationType = ImplementationType;
            var contextType = typeof(TestRunContext);
            var testResultType = typeof(TestResult);

            var objects = new object[ConstructorParameters.Length];
            for (int i = 0; i < ConstructorParameters.Length; i++) {
                if (contextType.IsAssignableFrom(ConstructorParameters[i].ParameterType)) {
                    objects[i] = context;
                } else if (testResultType.IsAssignableFrom(ConstructorParameters[i].ParameterType)) {
                    var tr = results.FirstOrDefault(c => c.GetType() == ConstructorParameters[i].ParameterType);
                    if (tr == null) {
                        Debugger.Break(); // this should never happen!
                                          // when we get here, we have a constructor with a TestResult object
                                          // that does not exist in the results list
                        throw new MethodAccessException("Cannot find dependency for one of the parameters of " + implementationType.FullName);
                    }
                    objects[i] = tr;
                } else {
                    Debugger.Break(); // this should never happen!
                                      // when we get here, we have a constructor with an object that
                                      // is not of type TestRunContext or TestResult
                    throw new MethodAccessException("Invalid parameter type in constructor of " + implementationType.FullName);
                }
            }
            if (Activator.CreateInstance(implementationType, objects) is not TestImplementation result)
                throw new MethodAccessException("Could not initialize " + implementationType.FullName);
            return result;
        }
        [JsonIgnore]
        public IEnumerable<Type> Dependencies {
            get {
                if (_dependencies == null) {
                    var testResultType = typeof(TestResult);
                    var thisType = this.GetType();
                    var cps = ConstructorParameters;
                    var dep = new List<Type>();
                    foreach (var cp in cps) {
                        if (testResultType.IsAssignableFrom(cp.ParameterType) && cp.ParameterType != thisType) {
                            dep.Add(cp.ParameterType);
                        }
                    }
                    _dependencies = dep;
                }
                return _dependencies;
            }
        }
        private IEnumerable<Type>? _dependencies;

        public async Task Run(TestRun testRun) {
            this.StartedAt = DateTime.Now;
            try {
                this.TestLog.HasThrown = false;
                var implementation = CreateImplementation(testRun.Context with { Log = this.TestLog }, testRun.TestResults);
                await implementation.Run();
            } catch (Exception e) {
                this.TestLog.HasThrown = true;
                this.TestLog.Log(e);
                this.Outcome = TestOutcomes.Failed; // test crashed; we don't know why, so don't report a result
#if DEBUG
                Debugger.Break();
#endif
            } finally {
                this.TestLog.Outcome = this.Outcome;
            }
        }

    }
    public abstract class TestResult<T> : TestResult, IHasInfo {
        public TestResult(string testId) : base(testId) { }
        [JsonProperty]
        public T? ExtraInfo { get; set; }

        object? IHasInfo.ExtraInfo => this.ExtraInfo;
    }
    public interface IHasInfo {
        public object? ExtraInfo { get; }
    }
}
