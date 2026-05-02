namespace Ashlar.Security.Hashing;

public interface ISessionTokenHasher
{
    string HashToken(string token);
}
