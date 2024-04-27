using OAuch.Shared;
using System.Net.Http;

namespace OAuch.Protocols.Http {
    public class HttpMethods : Enumeration {
        public static readonly HttpMethods Get = new(1, "GET");
        public static readonly HttpMethods Post = new(2, "POST");

        private HttpMethods(int id, string name) : base(id, name) { }
        public HttpMethod ToHttpMethod() {
            if (this.Id == Get.Id)
                return HttpMethod.Get;
            else
                return HttpMethod.Post;
        }
    }
}
