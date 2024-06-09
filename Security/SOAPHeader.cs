using System.Xml.Serialization;

namespace SoapApi.Security
{
    public partial class SOAPHeader
    {
        [XmlElement(Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")]
        public SOAPSecurity? Security { get; set; }

        [XmlElement(ElementName = "SessionToken", Namespace = "")]
        public string? SessionToken { get; set; }
    }
}
