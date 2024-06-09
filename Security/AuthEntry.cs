namespace SoapApi.Security
{
    public class AuthEntry
    {
        public AuthEntry(string userId, string username, string password)
        {
            UserID = userId;
            Username = username;
            Password = password;
        }

        public string UserID { get; }
        public string Username { get; }
        public string Password { get; }
    }

}
