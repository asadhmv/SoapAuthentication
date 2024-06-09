namespace SoapApi.Security.Authentication
{
    public interface IPasswordEncoder
    {
        public string Encode(string rawPassword);

        public (bool matches, bool needsUpgrade) Matches(string rawPassword, string encodedPassword);
}

}