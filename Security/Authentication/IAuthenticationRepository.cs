using System.Security.Claims;

namespace SoapApi.Security.Authentication
{

    public interface IAuthenticationRepository
    {
        Task<bool> AuthenticateUserAsync(ClaimsPrincipal principal, object? authData);
    }

}
