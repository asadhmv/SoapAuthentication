using System.Xml.Serialization;

namespace SoapApi.Security
{
    public partial class SOAPUsernameToken
    {
        [XmlAttribute(Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
        public string? Id { get; set; }

        public string? Username { get; set; }

        public Password? Password { get; set; }

        public string? Nonce { get; set; }

        [XmlElement(Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
        public DateTime? Created { get; set; }
    }
    public class Password
    {
        [XmlText]
        public string? Value { get; set; }

        [XmlAttribute("Type")]
        public string? Type { get; set; }
    }
}
