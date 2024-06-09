namespace SoapApi.Security
{
    public class SOAPAuthData
    {
        public static string RequestKey_SOAPAuthData = "SOAPAuthData";

        public SOAPHeader? Header { get; set; }

        public string? RequestedSOAPOperationName { get; set; }
    }

}
