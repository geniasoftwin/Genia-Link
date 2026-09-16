using System.Security.Authentication;

namespace GeniaLink.Core.Network;

public sealed class TrustedSessionRevokedException : AuthenticationException
{
    private const string DefaultMessage = "The trusted peer session was invalidated because trust was revoked or forgotten.";

    public TrustedSessionRevokedException()
        : base(DefaultMessage)
    {
    }

    public TrustedSessionRevokedException(string message)
        : base(message)
    {
    }

    public TrustedSessionRevokedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
