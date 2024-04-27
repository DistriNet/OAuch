using System;

namespace OAuch.Compliance.Tests.Shared {
    public interface ITimeDelayedTest {
        public DateTime? ResumeWhen { get; }
    }
}
