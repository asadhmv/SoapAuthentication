using Microsoft.AspNetCore.Mvc;
using System.Globalization;

namespace SoapApi.Security
{
    public enum SOAPVersion
    {
        v1_1,
        v1_2
    }
    public class SOAPControllerAttribute : ProducesAttribute
    {
        public SOAPVersion SOAPVersion { get; }

        public SOAPControllerAttribute(SOAPVersion soapVersion) : base(System.Net.Mime.MediaTypeNames.Application.Xml)
        {
            SOAPVersion = soapVersion;
        }
    }
}
