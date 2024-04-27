using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuch.Database;
using OAuch.Helpers;
using OAuch.Hubs;
using OAuch.LogConverters;
using OAuch.Protocols.Http;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared.Interfaces;
using OAuch.Shared.Logging;
using OAuch.TestRuns;
using System;
using System.IO.Compression;
using System.Linq;

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

            services.AddAuthentication(options => {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => {
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
            services.AddResponseCompression(options => {
                options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(
                    [
                        "application/javascript",
                        "application/json;",
                        "application/xml",
                        "text/css",
                        "text/html",
                        "text/json",
                        "text/plain",
                        "text/xml"
                    ]);
                options.EnableForHttps = true;
                options.Providers.Add<BrotliCompressionProvider>();
                options.Providers.Add<GzipCompressionProvider>();
            });
            builder.Services.Configure<BrotliCompressionProviderOptions>(options => {
                options.Level = CompressionLevel.Fastest;
            });
            builder.Services.Configure<GzipCompressionProviderOptions>(options => {
                options.Level = CompressionLevel.Optimal;
            });

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
                context.Response.Headers["X-Frame-Options"] = "DENY";
                context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' www.google.com www.gstatic.com; style-src 'self' 'unsafe-inline' code.ionicframework.com fonts.googleapis.com; font-src 'self' code.ionicframework.com fonts.gstatic.com; frame-src www.google.com; frame-ancestors 'none'; navigate-to *; img-src 'self' www.gstatic.com;";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                context.Response.Headers["Feature-Policy"] = "geolocation 'none';midi 'none';notifications 'none';push 'none';sync-xhr 'none';microphone 'none';camera 'none';magnetometer 'none';gyroscope 'none';speaker 'self';vibrate 'none';fullscreen 'self';payment 'none';accelerometer 'none';ambient-light-sensor 'none';autoplay 'none';document-write 'none';usb 'none'";
                context.Response.Headers["Permissions-Policy"] = "geolocation=();midi=();notifications=();push=();sync-xhr=();microphone=();camera=();magnetometer=();gyroscope=();speaker=(self);vibrate=();fullscreen=(self);payment=();accelerometer=();ambient-light-sensor=();autoplay=();document-write=();usb=()";
                await next.Invoke();
            });

#if !DEBUG 
            app.UseResponseCompression(); // Response Compression interferes with injected debug script from Visual Studio; only enable it on RELEASE
#endif
            app.UseHttpsRedirection();

            // rewrite www.oauch.io to oauch.io
            var options = new RewriteOptions();
            options.Rules.Add(new NonWwwRule());
            app.UseRewriter(options);

            app.UseStaticFiles();

            app.UseRouting();
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