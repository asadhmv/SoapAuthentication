using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Xml;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Options;
using SoapApi.Security.Authentication.Handler;
using SoapApi.Security.Authentication;
using SoapApi.Security;
using System.Text;
using Microsoft.Extensions.Internal;
using SoapApi.Security.Authentication.JWT;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace SoapApi.Security.Authentication.Handler;

public class SOAPAuthenticationHandler : AuthenticationHandler<SOAPAuthenticationHandlerOptions>
{
    private readonly IAuthenticationRepository _authNRepository;
    private readonly string? _jwtSecretKey;
    protected string? authErrorMessage;

    public SOAPAuthenticationHandler(IOptionsMonitor<SOAPAuthenticationHandlerOptions> options, ILoggerFactory loggerFactory,UrlEncoder encoder, Microsoft.Extensions.Internal.ISystemClock clock, IAuthenticationRepository authNRepository, IConfiguration configuration) : base(options, loggerFactory, encoder)
    {
        _authNRepository = authNRepository;
        _jwtSecretKey = configuration["Jwt:SecretKey"];
    }

    //Function that Handles Authentication and returns an AuthenticateResult representing the authentication status (Success or Failed)
    protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        HttpRequest request = Context.Request;


        //if (request.Headers.ContainsKey("Authorization") &&
        //    request.Headers["Authorization"].ToString().StartsWith("Bearer "))
        //{
        //    var token = request.Headers["Authorization"].ToString().Substring("Bearer ".Length);
        //    var tokenResponse = ValidateJwtToken(token);

        //    if (tokenResponse == null)
        //    {
        //        return AuthenticateResult.Fail("Invalid JWT Token");
        //    }

        //    var ticket = new AuthenticationTicket(tokenResponse, SOAPAuthenticationDefaults.AuthenticationScheme);
        //    return AuthenticateResult.Success(ticket);
        //}



        var readResult = await ReadAuthenticationDataAsync(request);
        SOAPAuthData? authData = readResult.authData;
        string? errorMsg = readResult.errorMessage;

        request.Body.Position = 0;


        if (errorMsg is not null)
        {
            authErrorMessage = errorMsg;
            return AuthenticateResult.Fail("Error Found : " + authErrorMessage);
        }

        // Validation
        if (authData is null)
        {
            authErrorMessage = "SOAP Header is empty or incorrect type";
            return AuthenticateResult.Fail(authErrorMessage);
        }
        Console.WriteLine(authData.Header);


        // Check for session token first
        if (authData.Header?.SessionToken != null)
        {
            var token = authData.Header.SessionToken;
            var tokenResponse = ValidateJwtToken(token);

            if (tokenResponse == null)
            {
                return AuthenticateResult.Fail("Invalid JWT Token");
            }

            var ticket = new AuthenticationTicket(tokenResponse, SOAPAuthenticationDefaults.AuthenticationScheme);
            return AuthenticateResult.Success(ticket);
        }



        if (authData.Header?.Security?.UsernameToken?.Username is null)
        {
            return AuthenticateResult.Fail("SOAP Security UsernameToken Username is missing");
        }
        if (authData.Header.Security.UsernameToken.Password is null)
        {
            return AuthenticateResult.Fail("SOAP Security UsernameToken Password is missing");
        }
        if (String.IsNullOrEmpty(authData.RequestedSOAPOperationName))
        {
            authErrorMessage = "SOAPOperationName was not found";
            return AuthenticateResult.Fail(authErrorMessage);
        }

        // Create the principal & identity
        ClaimsPrincipal principal = new ClaimsPrincipal();
        ClaimsIdentity identity = new ClaimsIdentity(SOAPAuthenticationDefaults.AuthenticationScheme + "Identity");
        principal.AddIdentity(identity);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, authData.Header.Security.UsernameToken.Username));

        // Authenticate the user
        if (await _authNRepository.AuthenticateUserAsync(principal, authData.Header.Security.UsernameToken.Password.Value))
        {
            // Generate JWT token
            var token = JwtTokenHelper.GenerateJwtToken(authData.Header.Security.UsernameToken.Username, _jwtSecretKey);

            // Add the header into the request context so Auth Handlers can use it.
            Context.Items.Add(SOAPAuthData.RequestKey_SOAPAuthData, authData);

            // Include JWT token in the response header
            Context.Response.OnStarting(async () =>
            {
                var responseXml = $@"
                <soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>
                    <soapenv:Header>
                        <SessionToken>{token}</SessionToken>
                    </soapenv:Header>
                    <soapenv:Body></soapenv:Body>
                </soapenv:Envelope>";
                var bytes = Encoding.UTF8.GetBytes(responseXml);
                Context.Response.ContentLength = bytes.Length;
                Context.Response.ContentType = "text/xml";
                await Context.Response.Body.WriteAsync(bytes, 0, bytes.Length);
            });

            AuthenticationTicket ticket = new AuthenticationTicket(principal, SOAPAuthenticationDefaults.AuthenticationScheme);
            return AuthenticateResult.Success(ticket);
        }
        else
            return AuthenticateResult.Fail("Authentication Failed");
    }



    private ClaimsPrincipal? ValidateJwtToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_jwtSecretKey);
        try
        {
            var claimsPrincipal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            return claimsPrincipal;
        }
        catch
        {
            return null;
        }
    }





    //Function to read and extract from xml the authentication data
    protected virtual async Task<(SOAPAuthData? authData, string? errorMessage)> ReadAuthenticationDataAsync(HttpRequest request)
    {
        request.EnableBuffering();
        request.Body.Position = 0;


        using (var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true))
        {
            SOAPAuthData? authData = null;
            string? errorMsg = null;

            try
            {
                var requestBody = await reader.ReadToEndAsync();
                Console.WriteLine(requestBody);
                // Load the XML content into an XmlDocument
                requestBody = requestBody.Replace("xmlns=", "xmlns:default=");
                //requestBody = requestBody.Replace("soapenv", "env");

                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(requestBody);

                // Create a namespace manager to handle the namespaces in the XML
                XmlNamespaceManager nsmgr = new XmlNamespaceManager(xmlDoc.NameTable);
                nsmgr.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");
                nsmgr.AddNamespace("soapenv", "http://schemas.xmlsoap.org/soap/envelope/");
                nsmgr.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
                nsmgr.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
                nsmgr.AddNamespace("ser", "http://some.com/service/");
                nsmgr.AddNamespace("tem", "http://tempuri.org/");

                // Extract the Header element
                XmlNode? headerNode = xmlDoc.SelectSingleNode("//soapenv:Header", nsmgr);
                SOAPHeader? header = null;
                if (headerNode != null)
                {
                    XmlSerializerNamespaces headerNamespaces = new XmlSerializerNamespaces();
                    headerNamespaces.Add("soap", "http://schemas.xmlsoap.org/soap/envelope/");
                    headerNamespaces.Add("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
                    headerNamespaces.Add("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
                    headerNamespaces.Add("tem", "http://tempuri.org/");


                    XmlSerializer headerSerializer = new XmlSerializer(typeof(SOAPHeader), new XmlRootAttribute("Header")
                    {
                        Namespace = "http://schemas.xmlsoap.org/soap/envelope/"
                    });

                    using (var headerReader = new StringReader(headerNode.OuterXml))
                    {
                        header = (SOAPHeader?)headerSerializer.Deserialize(headerReader);
                    }
                }

                // Extract the Body element
                XmlNode? bodyNode = xmlDoc.SelectSingleNode("//soapenv:Body", nsmgr);
                string? bodyContent = null;
                if (bodyNode != null)
                {
                    bodyContent = bodyNode.InnerXml;
                    Console.WriteLine("Body Element:");
                    Console.WriteLine(bodyContent);
                }
                authData = new SOAPAuthData
                {
                    Header = header,
                    RequestedSOAPOperationName = bodyNode?.FirstChild?.LocalName // Assuming the operation name is the first child of the body
                };


                // Log the deserialized data
                Console.WriteLine($"RequestedSOAPOperationName: {authData.RequestedSOAPOperationName}");
                if (authData.Header != null && authData.Header.Security != null && authData.Header.Security.UsernameToken != null)
                {
                    var token = authData.Header.Security.UsernameToken;
                    Console.WriteLine($"Username: {token.Username}");
                    Console.WriteLine($"Password: {token.Password?.Value}");
                    Console.WriteLine($"Nonce: {token.Nonce}");
                    //Console.WriteLine($"Created: {token.Created}");
                }
            }
            catch (Exception ex)
            {
                errorMsg = $"Error deserializing XML: {ex.Message}";
                Console.WriteLine(errorMsg);
                errorMsg = "Bad Request";
            }

            if (authData == null)
            {
                return (authData, errorMsg);
            }

            request.Body.Position = 0;

            return (authData, errorMsg);
        }
    }

}

















//SOAPAuthData? authData = new SOAPAuthData();
//string? errorMsg = null;
//try
//{
//    var requestBody = await red.ReadToEndAsync();

//    // Reset the request body stream position so it can be read again later
//    request.Body.Position = 0;

//    // Log the XML content to the console
//    //Console.WriteLine("Received XML:");
//    //Console.WriteLine(requestBody);

//    XmlDocument xmlDoc = new XmlDocument();
//    xmlDoc.LoadXml(requestBody);

//    // Create a namespace manager to handle the namespaces in the XML
//    XmlNamespaceManager nsmgr = new XmlNamespaceManager(xmlDoc.NameTable);
//    nsmgr.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");
//    nsmgr.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
//    nsmgr.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
//    nsmgr.AddNamespace("ser", "http://some.com/service/");




//    // Extract the Envelope element
//    XmlNode? envelopeNode = xmlDoc.SelectSingleNode("//soap:Envelope", nsmgr);
//    if (envelopeNode != null)
//    {
//        Console.WriteLine("Envelope Element:");
//        Console.WriteLine(envelopeNode.OuterXml);

//        // Extract the Header element
//        XmlNode? headerNode = envelopeNode.SelectSingleNode("soap:Header", nsmgr);
//        if (headerNode != null)
//        {

//            Console.WriteLine("Header Element:");
//            Console.WriteLine(headerNode.OuterXml);

//            // Extract the Security element
//            XmlNode? securityNode = headerNode.SelectSingleNode("wsse:Security", nsmgr);
//            if (securityNode != null)
//            {
//                Console.WriteLine("Security Element:");
//                Console.WriteLine(securityNode.OuterXml);

//                // Extract the UsernameToken element
//                XmlNode? usernameTokenNode = securityNode.SelectSingleNode("wsse:UsernameToken", nsmgr);
//                if (usernameTokenNode != null)
//                {
//                    Console.WriteLine("UsernameToken Element:");
//                    Console.WriteLine(usernameTokenNode.OuterXml);

//                    SOAPUsernameToken usernameToken = new SOAPUsernameToken();

//                    // Extract and log individual child elements
//                    XmlNode? usernameNode = usernameTokenNode.SelectSingleNode("wsse:Username", nsmgr);
//                    XmlNode? passwordNode = usernameTokenNode.SelectSingleNode("wsse:Password", nsmgr);
//                    XmlNode? nonceNode = usernameTokenNode.SelectSingleNode("wsse:Nonce", nsmgr);
//                    XmlNode? createdNode = usernameTokenNode.SelectSingleNode("wsu:Created", nsmgr);



//                    if (usernameNode != null && passwordNode != null)
//                    {
//                        usernameToken.Username = usernameNode.InnerText;
//                        Console.WriteLine($"Username: {usernameNode.InnerText}");
//                        Password password = new Password();
//                        password.Value = passwordNode.InnerText;
//                        password.Type = "password";
//                        usernameToken.Password = password;
//                        Console.WriteLine($"Password: {passwordNode.InnerText}");
//                        authData.Header.Security = usernameToken;
//                    }
//                    else
//                    {
//                        Console.WriteLine("Username or Password missing");
//                        authData = null;
//                        errorMsg = "Payload is missing a Username or Password";
//                    }
//                    if (nonceNode != null)
//                    {
//                        usernameToken.Nonce = nonceNode.InnerText;
//                        Console.WriteLine($"Nonce: {nonceNode.InnerText}");
//                    }
//                    if (createdNode != null)
//                    {
//                        Console.WriteLine($"Created: {createdNode.InnerText}");
//                    }
//                }
//                else
//                {
//                    Console.WriteLine("UsernameToken Element not found.");
//                    errorMsg = "Payload is missing a UsernameToken";
//                    authData = null;

//                }
//            }
//            else
//            {
//                Console.WriteLine("Security Element not found.");
//                errorMsg = "Payload is missing a Security";
//                authData = null;

//            }
//        }
//        else
//        {
//            Console.WriteLine("Header Element not found.");
//            errorMsg = "Payload is missing a Header";
//            authData = null;

//        }

//        // Extract the Body element
//        XmlNode? bodyNode = envelopeNode.SelectSingleNode("soap:Body", nsmgr);
//        if (bodyNode != null)
//        {
//            Console.WriteLine("Body Element:");
//            Console.WriteLine(bodyNode.OuterXml);
//        }
//        else
//        {
//            Console.WriteLine("Body Element not found.");
//            errorMsg = "Payload is missing a Body";
//            authData = null;

//        }
//    }
//    else
//    {
//        Console.WriteLine("Envelope Element not found.");
//        errorMsg = "Payload is missing a Header";
//        authData = null;

//    }
//}
//catch (Exception e)
//{
//    errorMsg = e.ToString();
//}
//return (authData, errorMsg);







//request.Body.Position = 0;
//XmlReaderSettings settings = new XmlReaderSettings
//{
//    Async = true,
//    IgnoreWhitespace = true
//};

//using XmlReader reader = XmlReader.Create(request.Body, settings);
//string soapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
//SOAPAuthData? authData = new SOAPAuthData();
//string? errorMsg = null;
//try
//{
//    while (await reader.ReadAsync())
//    {
//        Console.WriteLine(reader);
//        if (reader.IsStartElement() && reader.LocalName == "Envelope" && reader.NamespaceURI == soapNamespace)
//        {
//            bool bBodyFound = false;
//            bool bHeaderFound = false;
//            bool bDataRead = await reader.ReadAsync();
//            while (bDataRead && (!bBodyFound || !bHeaderFound))
//            {
//                if (reader.IsStartElement() && reader.LocalName == "Body" && reader.NamespaceURI == soapNamespace)
//                {
//                    bBodyFound = true;
//                    reader.ReadStartElement();
//                    authData.RequestedSOAPOperationName = reader.LocalName;
//                    await reader.SkipAsync();
//                }
//                if (reader.IsStartElement() && reader.LocalName == "Header" && reader.NamespaceURI == soapNamespace)
//                {
//                    Console.WriteLine("Reading Soap Header");
//                    bHeaderFound = true;
//                    XmlRootAttribute root = new XmlRootAttribute("Header");
//                    XmlSerializer serializer = new XmlSerializer(typeof(SOAPHeader), null, null, root, soapNamespace);
//                    authData.Header = serializer.Deserialize(reader) as SOAPHeader;
//                    Console.WriteLine(serializer.Deserialize(reader));
//                    continue;
//                }
//                bDataRead = await reader.ReadAsync();
//            }
//            if (!bBodyFound || !bHeaderFound)
//            {
//                authData = null;
//                errorMsg = "Payload is missing a Header or a Body";
//            }
//            break;
//        }
//    }
//}
//catch (Exception ex)
//{
//    authData = null;
//    errorMsg = ex.Message;
//    if (request.Body.Position == 0) // Makes the error consistent with other missing payload errors
//        errorMsg = "Request is missing a payload";
//}
//finally
//{
//    // Reset the stream position so Model Binding can re-read the stream
//    request.Body.Position = 0;
//}
//return (authData, errorMsg);
