//using Microsoft.Extensions.DependencyInjection.Extensions;
//using SoapApi;
//using SoapApi.Services;
//using SoapCore;

//var builder = WebApplication.CreateBuilder(args);

//builder.Services.AddSoapCore();
//builder.Services.AddSingleton<ITodoService, TodoService>();
//builder.Services.AddSingleton<ILoginService, LoginService>();
//builder.Services.AddSoapExceptionTransformer((ex) => ex.Message);
//builder.Services.AddMvc();

//var app = builder.Build();

////app.UseSoapEndpoint<ITodoService>;
////app.UseSoapEndpoint<ITodoService>("/Todo.asmx", new SoapEncoderOptions(), SoapSerializer.XmlSerializer);

////endpoints.UseSoapEndpoint<ILoginService>("/Login.asmx", new SoapEncoderOptions(), SoapSerializer.XmlSerializer);
////});
//app.UseRouting();
//app.UseEndpoints((endpoints) =>
//{
//    endpoints.UseSoapEndpoint<ITodoService>("/Todo.asmx", new SoapEncoderOptions(), SoapSerializer.XmlSerializer, behavior: new HeaderInspectorBehavior());
//    endpoints.UseSoapEndpoint<ILoginService>("/Login.asmx", new SoapEncoderOptions(), SoapSerializer.XmlSerializer, behavior: new HeaderInspectorBehavior());
//});

//app.Run();


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace Server
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                .UseKestrel()
                .UseUrls("https://*:5050")
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseStartup<Startup>()
                .ConfigureLogging(x =>
                {
                    x.AddDebug();
                    x.AddConsole();
                })
                .Build();

            host.Run();
        }
    }
}
