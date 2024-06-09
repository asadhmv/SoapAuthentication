using System.Text.Json;
namespace SoapApi.Security.Authentication.DataStore;

public static class JsonElementExtensions
{
    public static string GetMandatoryString(this JsonElement parentElement, string propertyName)
    {
        JsonElement element;
        if (!parentElement.TryGetProperty(propertyName, out element))
            throw new Exception($"{propertyName} is mandatory in the Auth Information File");

        return element.ToString();
    }
}
