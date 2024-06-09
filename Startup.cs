
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using SoapApi.Services;
using SoapCore;
using SoapApi.Security.Authentication.Handler;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace Server
{
    public class Startup
    {
        //public IConfiguration Configuration { get; }
        //public Startup(IConfiguration configuration)
        //{
        //    Configuration = configuration;
        //}

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSoapCore();
            services.AddSingleton<ITodoService, TodoService>();
            services.AddMvc();
            services.AddHttpContextAccessor();
            services.AddSingleton<SOAPAuthenticationHandler>();


            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = SOAPAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = SOAPAuthenticationDefaults.AuthenticationScheme;
            }).AddSOAP_FileDataStore();

            services.AddAuthorization();
        }
        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.UseSoapEndpoint<ITodoService>("/Todo.asmx", new SoapEncoderOptions(), SoapSerializer.XmlSerializer).RequireAuthorization();
            });
        }
    }
}