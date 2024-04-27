namespace OAuch.ViewModels {
    public class CallbackViewModel {
        public CallbackViewModel(string formParameters) {
            this.FormParameters = formParameters;
        }
        public string FormParameters { get; set; }
    }
}
