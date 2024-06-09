using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.WebUtilities;


namespace SoapApi.Security.Authentication
{

    public class PasswordEncoder : IPasswordEncoder
    {
        private const int SaltSize = 16; // 128 bit
        private const int KeySize = 32; // 256 bit
        private PasswordEncoderOptions Options { get; }

        public PasswordEncoder(IOptions<PasswordEncoderOptions> options)
        {
            Options = options.Value;
        }

        public string Encode(string rawPassword)
        {
            using (var algorithm = new Rfc2898DeriveBytes(
                rawPassword,
                SaltSize,
                Options.Iterations,
                HashAlgorithmName.SHA256))
            {
                var key = WebEncoders.Base64UrlEncode(algorithm.GetBytes(KeySize));
                var salt = WebEncoders.Base64UrlEncode(algorithm.Salt);
                return $"{Options.Iterations}.{salt}.{key}";
            }
        }

        public (bool matches, bool needsUpgrade) Matches(string rawPassword, string encodedPassword)
        {
            var parts = encodedPassword.Split('.', 3);
            if (parts.Length != 3)
            {
                throw new FormatException("Unexpected hash format. Should be formatted as `{iterations}.{salt}.{hash}`");
            }

            var iterations = Convert.ToInt32(parts[0]);
            var salt = WebEncoders.Base64UrlDecode(parts[1]);
            var key = WebEncoders.Base64UrlDecode(parts[2]);
            var needsUpgrade = iterations != Options.Iterations;

            using (var algorithm = new Rfc2898DeriveBytes(
                rawPassword,
                salt,
                iterations,
                HashAlgorithmName.SHA256))
            {
                var keyToCheck = algorithm.GetBytes(KeySize);
                var verified = keyToCheck.SequenceEqual(key);

                return (verified, needsUpgrade);
            }
        }
    }

}
