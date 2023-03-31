using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class LogViewModel {
        public LogViewModel(string contents) {
            this.Contents = contents;
        }
        public string Contents { get; set; }
    }
}
