using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuch.LogConverters;
using OAuch.Protocols.Http;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Shared.Logging;
using OAuch.Helpers;
using OAuch.Database;
using OAuch.Hubs;
using OAuch.TestRuns;
using OAuch.Protocols.OAuth2;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Rewrite;
using OAuch.Shared.Interfaces;

namespace OAuch {
    public class Startup {
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {
            var builder = services.AddControllersWithViews();
            services.AddDbContext<OAuchDbContext>();
            services.AddSignalR();
            //services.AddHsts(options => {  // HSTS must be disabled, or the non-oauch.io-redirects won't work
            //    options.Preload = true;
            //    options.IncludeSubDomains = true;
            //    options.MaxAge = TimeSpan.FromSeconds(63072000);
            //});

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.LoginPath = "/Home";
                    options.ClaimsIssuer = "OAUCH";
                });


            // add logging services
            services.AddSingleton<ILogConverter<Exception>>(new ExceptionConverter());
            services.AddSingleton<ILogConverter<HttpRequest>>(new HttpRequestConverter());
            services.AddSingleton<ILogConverter<HttpResponse>>(new HttpResponseConverter());
            services.AddSingleton<ILogConverter<JsonWebToken>>(new JsonWebTokenConverter());
            services.AddSingleton<ILogConverter<JwkSet>>(new JwkSetConverter());
            services.AddSingleton<ILogConverter<CertificateReport>>(new CertificateReportConverter());
            services.AddSingleton<ILogConverter<RedirectConverter.RedirectInfo>>(new RedirectConverter());
            services.AddSingleton<ILogConverter<CallbackResult>>(new CallbackConverter());
            services.AddSingleton<ILogConverter<TokenResult>>(new TokenResultConverter());
            services.AddSingleton<ICertificateResolver>(new CertificateResolver());
            services.AddRazorPages();

#if DEBUG
            builder.AddRazorRuntimeCompilation();
#endif
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
            if (env.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            } else {
                app.UseExceptionHandler("/Home/Error");
                //app.UseHsts(); // HSTS must be disabled, or the non-oauch.io-redirects won't work
            }
            app.Use(async (context, next) => {
                /* Do not add Strict-Transport-Security */
                context.Response.Headers.Add("X-Frame-Options", "DENY");
                context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
                context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' www.google.com www.gstatic.com; style-src 'self' 'unsafe-inline' code.ionicframework.com fonts.googleapis.com; font-src 'self' code.ionicframework.com fonts.gstatic.com; frame-src www.google.com; frame-ancestors 'none'; navigate-to *; img-src 'self' www.gstatic.com;");
                context.Response.Headers.Add("Referrer-Policy", "no-referrer");
                context.Response.Headers.Add("Feature-Policy", "geolocation 'none';midi 'none';notifications 'none';push 'none';sync-xhr 'none';microphone 'none';camera 'none';magnetometer 'none';gyroscope 'none';speaker 'self';vibrate 'none';fullscreen 'self';payment 'none';accelerometer 'none';ambient-light-sensor 'none';autoplay 'none';document-write 'none';usb 'none'");
                context.Response.Headers.Add("Permissions-Policy", "geolocation=();midi=();notifications=();push=();sync-xhr=();microphone=();camera=();magnetometer=();gyroscope=();speaker=(self);vibrate=();fullscreen=(self);payment=();accelerometer=();ambient-light-sensor=();autoplay=();document-write=();usb=()");
                await next.Invoke();
            });

            app.UseHttpsRedirection();

            // rewrite www.oauch.io to oauch.io
            var options = new RewriteOptions();
            options.Rules.Add(new NonWwwRule());
            app.UseRewriter(options);

            app.UseStaticFiles();

            app.UseRouting();
            //app.UseDummyAuthentication();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapHub<TestRunHub>("/testrunhub");
                endpoints.MapControllerRoute(
                    "catch all to callback",
                    "{*url}",
                    new { controller = "Callback", action = "Caught" });
            });
        }
    }
}