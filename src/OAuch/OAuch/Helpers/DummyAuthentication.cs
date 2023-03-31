using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace OAuch.Helpers {
    public class DummyAuthenticationMiddleware {
        private readonly RequestDelegate _next;

        public DummyAuthenticationMiddleware(RequestDelegate next) {
            _next = next;
        }

        public async Task Invoke(HttpContext context) {
            // Do something with context near the beginning of request processing.


            context.User = new System.Security.Claims.ClaimsPrincipal(new GenericIdentity("OAuch User"));

            await _next.Invoke(context);

            // Clean up.
        }
    }
    public static class DummyAuthenticationExtensions {
        public static IApplicationBuilder UseDummyAuthentication(this IApplicationBuilder builder) {
            return builder.UseMiddleware<DummyAuthenticationMiddleware>();
        }
    }
}
