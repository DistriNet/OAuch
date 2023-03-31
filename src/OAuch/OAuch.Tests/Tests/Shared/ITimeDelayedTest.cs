using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public interface ITimeDelayedTest {
        public DateTime? ResumeWhen { get; }
    }
}
