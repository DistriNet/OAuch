using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests {
    public class TestResultFormatter {
        public TestResultFormatter(string countermeasureFullyImplemented = "YES", string countermeasurePartiallyImplemented = "PARTIAL", string countermeasureNotImplemented = "NO", string skipped = "SKIPPED", string failed = "TEST FAILED") {
            this.CountermeasurePartiallyImplemented = countermeasurePartiallyImplemented;
            this.CountermeasureFullyImplemented = countermeasureFullyImplemented;
            this.CountermeasureNotImplemented = countermeasureNotImplemented;
            this.Skipped = skipped;
            this.Failed = failed;
        }
        public string CountermeasureFullyImplemented { get; }
        public string CountermeasurePartiallyImplemented { get; }
        public string CountermeasureNotImplemented { get; }
        public string Skipped { get; }
        public string Failed { get; }
        public string Format(TestOutcomes? outcome) {
            if (outcome != null) {
                switch (outcome.Value) {
                    case TestOutcomes.SpecificationFullyImplemented:
                        return CountermeasureFullyImplemented;
                    case TestOutcomes.SpecificationPartiallyImplemented:
                        return CountermeasurePartiallyImplemented;
                    case TestOutcomes.SpecificationNotImplemented:
                        return CountermeasureNotImplemented;
                    case TestOutcomes.Failed:
                        return Failed;
                    case TestOutcomes.Skipped:
                        return Skipped;
                }
            }
            return "??";
        }

        public static TestResultFormatter YesGoodNoBad => new TestResultFormatter();
        public static TestResultFormatter YesBadNoGood => new TestResultFormatter("NO", countermeasureNotImplemented: "YES");
    }
}
