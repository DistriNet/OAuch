using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class CallbackViewModel {
        public CallbackViewModel(string formParameters) {
            this.FormParameters = formParameters;
        }
        public string FormParameters { get; set; }
    }
}
