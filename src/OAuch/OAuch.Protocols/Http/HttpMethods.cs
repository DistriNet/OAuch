using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using OAuch.Shared;

namespace OAuch.Protocols.Http {
    public class HttpMethods : Enumeration {
        public static HttpMethods Get = new HttpMethods(1, "GET");
        public static HttpMethods Post = new HttpMethods(2, "POST");

        private HttpMethods(int id, string name) : base(id, name) { }
        public HttpMethod ToHttpMethod() {
            if (this.Id == Get.Id)
                return HttpMethod.Get;
            else
                return HttpMethod.Post;
        }
    }
}
