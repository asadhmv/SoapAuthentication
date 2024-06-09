using Microsoft.AspNetCore.Authentication;
using SoapApi.Security.Authentication.DataStore;
using SoapApi.Security.Authentication.Handler;
using SoapApi.Security.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;


public static class SOAPAuthenticationBuilderExtensions
{
    public static AuthenticationBuilder AddSOAP_FileDataStore(this AuthenticationBuilder builder, Action<SOAPAuthenticationHandlerOptions> configureFileAuthenticationHandlerOptions)
        => builder.AddSOAP_FileDataStore(SOAPAuthenticationDefaults.AuthenticationScheme, configureFileAuthenticationHandlerOptions);

    public static AuthenticationBuilder AddSOAP_FileDataStore(this AuthenticationBuilder builder, string authenticationScheme, Action<SOAPAuthenticationHandlerOptions> configureFileAuthenticationHandlerOptions)
        => builder.AddSOAP_FileDataStore(authenticationScheme, null, configureFileAuthenticationHandlerOptions);

    public static AuthenticationBuilder AddSOAP_FileDataStore(this AuthenticationBuilder builder, string authenticationScheme = "SOAP", string displayName = "", Action<SOAPAuthenticationHandlerOptions> configureFileAuthenticationHandlerOptions = null, Action<PasswordEncoderOptions> configurePasswordEncoderOptions = null)
    {
        builder.AddScheme<SOAPAuthenticationHandlerOptions, SOAPAuthenticationHandler>(authenticationScheme, displayName, configureFileAuthenticationHandlerOptions);

        // Add a Password Encoder
        var encoderOptionsBuilder = builder.Services.AddOptions<PasswordEncoderOptions>();
        if (configurePasswordEncoderOptions is not null)
        {
            encoderOptionsBuilder.Configure(configurePasswordEncoderOptions);
        }
        builder.Services.AddSingleton<IPasswordEncoder, PasswordEncoder>();

        // Add a DataStore (File)
        builder.Services.AddSingleton<IAuthenticationRepository, FileAuthDataStore>();

        // Add JWT Bearer Authentication
        //var key = Encoding.ASCII.GetBytes("secret_key");
        //builder.Services.AddAuthentication(options =>
        //{
        //    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        //    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        //})
        //.AddJwtBearer(options =>
        //{
        //    options.RequireHttpsMetadata = false;
        //    options.SaveToken = true;
        //    options.TokenValidationParameters = new TokenValidationParameters
        //    {
        //        ValidateIssuerSigningKey = true,
        //        IssuerSigningKey = new SymmetricSecurityKey(key),
        //        ValidateIssuer = false,
        //        ValidateAudience = false,
        //        ClockSkew = TimeSpan.Zero
        //    };
        //});

        return builder;
    }
}
