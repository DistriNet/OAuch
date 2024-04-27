using OAuch.Shared.Enumerations;

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

        public static TestResultFormatter YesGoodNoBad => new();
        public static TestResultFormatter YesBadNoGood => new("NO", countermeasureNotImplemented: "YES");
    }
}
