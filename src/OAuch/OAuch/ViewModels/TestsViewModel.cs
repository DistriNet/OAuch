using OAuch.Compliance;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class TestsViewModel {
        public required IReadOnlyList<Test> Tests { get; set; }
    }
}
