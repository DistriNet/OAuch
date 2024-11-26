using Newtonsoft.Json;
using OAuch.Compliance.Tests;
using System;
using System.Diagnostics;

namespace OAuch.Compliance {
    public abstract class Test {
        [JsonIgnore]
        public string TestId {
            get {
                if (_id == null) {
                    _id = this.GetType().FullName;
                    if (_id == null)
                        throw new NotSupportedException(); // this cannot happen
                }
                return _id;
            }
        }
        private string? _id;

        public abstract string Title { get; }
        public abstract string Description { get; }
        public abstract TestResultFormatter ResultFormatter { get; }
        public override bool Equals(object? obj) {
            if (obj is not Test t)
                return false;
            return t.TestId == this.TestId;
        }
        public override int GetHashCode() {
            return this.GetType().GetHashCode();
        }

        public abstract Type ResultType { get; }
        public virtual TestResult CreateEmptyResult() {
            var resultType = ResultType;

            var consts = resultType.GetConstructors();
            if (consts.Length != 1) {
                Debugger.Break(); // this should never happen!
                                  // when we get here, we have created multiple (or none) public constructors on
                                  // one of our implementation types
                throw new MethodAccessException("Too many or not enough public constructors for type " + resultType.FullName);
            }

            var pars = consts[0].GetParameters();
            if (pars.Length != 1 || pars[0].ParameterType != typeof(string)) {
                Debugger.Break(); // this should never happen!
                                  // when we get here, we have created a constructor
                                  // that does not take a single string parameter
                throw new MethodAccessException("Invalid constructors for type " + resultType.FullName);
            }

            if (Activator.CreateInstance(resultType, [this.TestId]) is not TestResult result)
                throw new MethodAccessException("Could not initialize " + resultType.FullName);
            return result;
        }
    }
}