using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;

namespace SoapApi.Security.Authentication.DataStore;

public class FileAuthDataStore : IAuthenticationRepository
{
    private readonly ILogger<FileAuthDataStore> _logger;
    protected const string DefaultAuthDataStoreFolderName = "Security/Authentication/DataStore";
    protected const string DefaultAuthDataStoreFileName = "AuthData.json";
    protected const string AuthDataStoreFileNameConfigKey = "SOAPAuthenticationDataStore:FilePath";
    protected IDictionary<string, AuthEntry> users = new Dictionary<string, AuthEntry>{
            { "dd27d494-55f4-4912-a38e-626ddb019ac7", new AuthEntry("dd27d494-55f4-4912-a38e-626ddb019ac7", "user1", "10000.t8hio9zJxJGQQozkiJdsUg.B7xsYluz0BjEKUNJ_Yyycxheh_5baFvsS074mMHjPiE") },
            { "2", new AuthEntry("2", "user2", "password2") },
            { "3", new AuthEntry("3", "user3", "password3") }
        };
    protected IPasswordEncoder _passwordEncoder;

    public FileAuthDataStore(IConfiguration configuration, ILogger<FileAuthDataStore> logger, IPasswordEncoder passwordEncoder)
    {
        Console.WriteLine("FileAuthDataStore");
        _logger = logger;
        _passwordEncoder = passwordEncoder;
        string? filePath = configuration[AuthDataStoreFileNameConfigKey];
        if (filePath == null)
        {
            string? baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            if (baseDir == null)
                throw new FileNotFoundException("FileAuthDataStore cannot find the Auth Information File Directory.");

            string[] files = Directory.GetFiles(baseDir, DefaultAuthDataStoreFileName, SearchOption.TopDirectoryOnly);
            if (files.Length != 1)
            {
                files = Directory.GetFiles(baseDir, DefaultAuthDataStoreFileName, SearchOption.AllDirectories);
                if (files.Length == 0)
                    throw new FileNotFoundException("FileAuthDataStore cannot find the Auth Information File.");
                if (files.Length > 1)
                    throw new FileNotFoundException("FileAuthDataStore found more than one Auth Information File.");
            }
            filePath = files[0];
        }

        string jsonString = File.ReadAllText(filePath);
        using (JsonDocument document = JsonDocument.Parse(jsonString))
        {
            foreach (JsonElement userElement in document.RootElement.EnumerateArray())
            {
                string userId = userElement.GetProperty("UserID").GetString();
                string password = userElement.GetProperty("Password").GetString();
                AuthEntry user = new AuthEntry(userId, userElement.GetProperty("Username").GetString(), password);
                users.Add(user.Username, user);
            }
        }

        if (users.Count == 0)
        {
            _logger.LogWarning("No users added to Auth DataStore. This might break the Authentication mechanism.");
        }
    }


    //Function to authenticate user camparing the password input with the database information
    public virtual Task<bool> AuthenticateUserAsync(ClaimsPrincipal principal, object? authDataObject)
    {
        Console.WriteLine("AuthenticateUserAsync");
        bool isAuthenticated = false;
        Claim? userIdClaim = principal.Claims.FirstOrDefault(t => t.Type == ClaimTypes.NameIdentifier);
        if (userIdClaim != null)
        {
            if (users.ContainsKey(userIdClaim.Value))
            {

                AuthEntry userAuth = users[userIdClaim.Value];
                if (authDataObject == null || authDataObject.GetType() != typeof(string))
                {
                    return Task.FromResult(false);
                }

                string password = (string)authDataObject;

                (bool matches, bool needsUpgrade) = _passwordEncoder.Matches(password, userAuth.Password);
                isAuthenticated = matches;
                if (isAuthenticated && typeof(ClaimsIdentity).IsAssignableFrom(principal.Identity?.GetType()))
                {
                    ClaimsIdentity identity = (ClaimsIdentity)principal.Identity;
                    identity.AddClaim(new Claim(identity.NameClaimType, userAuth.Username));
                }
            }
            else
            {
                throw new FileNotFoundException($"User does not have the claim {ClaimTypes.NameIdentifier}");
            }
        }
        return Task.FromResult(isAuthenticated);
    }
}
