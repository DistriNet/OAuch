using System.Collections.Generic;
using System.Diagnostics;

namespace OAuch.Compliance.Threats {
    public abstract class Threat {
        public Threat() {
            DependsOnFeatures = new List<Test>();
            MitigatedBy = new List<TestCombination>();
        }
        private Test GetTest<T>() where T : Test {
            var t = typeof(T);
            Debug.Assert(t.FullName != null);
            var found = ComplianceDatabase.Tests.TryGetValue(t.FullName, out var result);
            Debug.Assert(found);
            return result!;
        }
        protected void AddDependency<T>() where T : Test => DependsOnFeatures.Add(GetTest<T>());
        protected void AddMitigation<T>() where T : Test => MitigatedBy.Add([GetTest<T>()]);
        protected void AddMitigation<T, U>() where T : Test where U : Test => MitigatedBy.Add([GetTest<T>(), GetTest<U>()]);
        protected void AddMitigation<T, U, V>() where T : Test where U : Test where V : Test => MitigatedBy.Add([GetTest<T>(), GetTest<U>(), GetTest<V>()]);
        protected void AddMitigation<T, U, V, W>() where T : Test where U : Test where V : Test where W : Test => MitigatedBy.Add([GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>()]);
        protected void AddMitigation<T, U, V, W, X>() where T : Test where U : Test where V : Test where W : Test where X : Test => MitigatedBy.Add([GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>(), GetTest<X>()]);
        protected void AddMitigation<T, U, V, W, X, Y>() where T : Test where U : Test where V : Test where W : Test where X : Test where Y : Test => MitigatedBy.Add([GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>(), GetTest<X>(), GetTest<Y>()]);
        protected void AddMitigation<T, U, V, W, X, Y, Z>() where T : Test where U : Test where V : Test where W : Test where X : Test where Y : Test where Z : Test => MitigatedBy.Add([GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>(), GetTest<X>(), GetTest<Y>(), GetTest<Z>()]);
        protected void AddMitigation<S, T, U, V, W, X, Y, Z>() where S : Test where T : Test where U : Test where V : Test where W : Test where X : Test where Y : Test where Z : Test => MitigatedBy.Add([GetTest<S>(), GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>(), GetTest<X>(), GetTest<Y>(), GetTest<Z>()]);
        protected void AddMitigation<S, T, U, V, W, X, Y, Z, Q>() where S : Test where T : Test where U : Test where V : Test where W : Test where X : Test where Y : Test where Z : Test where Q : Test => MitigatedBy.Add([GetTest<S>(), GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>(), GetTest<X>(), GetTest<Y>(), GetTest<Z>(), GetTest<Q>()]);
        protected void AddMitigation<S, T, U, V, W, X, Y, Z, Q, R>() where S : Test where T : Test where U : Test where V : Test where W : Test where X : Test where Y : Test where Z : Test where Q : Test where R : Test => MitigatedBy.Add([GetTest<S>(), GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>(), GetTest<X>(), GetTest<Y>(), GetTest<Z>(), GetTest<Q>(), GetTest<R>()]);
        protected void AddMitigation<S, T, U, V, W, X, Y, Z, Q, R, A>() where S : Test where T : Test where U : Test where V : Test where W : Test where X : Test where Y : Test where Z : Test where Q : Test where R : Test where A : Test => MitigatedBy.Add([GetTest<S>(), GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>(), GetTest<X>(), GetTest<Y>(), GetTest<Z>(), GetTest<Q>(), GetTest<R>(), GetTest<A>()]);
        protected void AddMitigation<S, T, U, V, W, X, Y, Z, Q, R, A, B>() where S : Test where T : Test where U : Test where V : Test where W : Test where X : Test where Y : Test where Z : Test where Q : Test where R : Test where A : Test where B : Test => MitigatedBy.Add([GetTest<S>(), GetTest<T>(), GetTest<U>(), GetTest<V>(), GetTest<W>(), GetTest<X>(), GetTest<Y>(), GetTest<Z>(), GetTest<Q>(), GetTest<R>(), GetTest<A>(), GetTest<B>()]);

        public abstract string Id { get; }
        public abstract string Title { get; }
        public abstract string Description { get; }
        public abstract OAuthDocument Document { get; }
        public abstract string LocationInDocument { get; }
        public abstract string? ExtraDescription { get; }
        public List<Test> DependsOnFeatures { get; } // if any of these tests (partially) succeeds, the vulnerability is considered relevant
        public List<TestCombination> MitigatedBy { get; } // if any of these tests (partially) succeeds, the vulnerability is considered (partially) mitigated
        public virtual string? AliasOf => null; //used for BCP threats that are an alias of threats in RFC6819

        // for backward compatibility
        public List<ThreatInstance> Instances => [new ThreatInstance { ExtraDescription = ExtraDescription, DependsOnFeatures = DependsOnFeatures, MitigatedBy = MitigatedBy }];
    }
    public class TestCombination : List<Test> {
        // this represents an AND-list of tests
        // ALL tests must (partially) succeed (or skipped - this means the test is irrelevant)
    }
    public class ThreatInstance {
        public string? ExtraDescription { get; init; }
        public required List<Test> DependsOnFeatures { get; init; } // if any of these tests (partially) succeeds, the vulnerability is considered relevant
        public required List<TestCombination> MitigatedBy { get; init; } // if any of these tests (partially) succeeds, the vulnerability is considered (partially) mitigated
    }
}
