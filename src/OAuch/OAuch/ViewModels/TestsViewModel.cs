using OAuch.Compliance;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class TestsViewModel {
        public required IReadOnlyList<Test> Tests { get; set; }
    }
}
