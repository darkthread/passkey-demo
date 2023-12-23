using System.Collections.Concurrent;
using System.Text.Json;

namespace Fido2NetLib.Development;

public class DevelopmentFileStore
{
    class StoreData
    {
        public ConcurrentDictionary<string, Fido2User> Users { get; set; } = new ConcurrentDictionary<string, Fido2User>();
        public List<StoredCredential> Credentials { get; set; } = new List<StoredCredential>();

    }

    private static string _filePath;
    static private StoreData _storeData = new StoreData();

    public void Sync()
    {
        lock (_storeData)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(_storeData, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(_filePath,json);
        }
    }

    public void Load()
    {
        lock (_storeData)
        {
            var json = File.ReadAllText(_filePath);
            _storeData = System.Text.Json.JsonSerializer.Deserialize<StoreData>(json)!;
        }

    }

    public DevelopmentFileStore(IWebHostEnvironment env)
    {
        _filePath = Path.Combine(env.ContentRootPath, "Data", "creds.json");
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        if (!File.Exists(_filePath)) Sync(); else Load();
    }

    public Fido2User GetOrAddUser(string username, Func<Fido2User> addCallback)
    {
        var user = _storeData.Users.GetOrAdd(username, addCallback());
        Sync();
        return user;
    }

    public Fido2User? GetUser(string username)
    {
        _storeData.Users.TryGetValue(username, out var user);
        return user;
    }

    public Fido2User? GetUserById(byte[] id)
    {
        return _storeData.Users.FirstOrDefault(u => u.Value.Id.AsSpan().SequenceEqual(id)).Value;
    }


    public List<StoredCredential> GetCredentialsByUser(Fido2User user)
    {
        return _storeData.Credentials.Where(c => c.UserId.AsSpan().SequenceEqual(user.Id)).ToList();
    }

    public StoredCredential? GetCredentialById(byte[] id)
    {
        return _storeData.Credentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(id));
    }

    public Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_storeData.Credentials.Where(c => c.UserHandle.AsSpan().SequenceEqual(userHandle)).ToList());
    }

    public void UpdateCounter(byte[] credentialId, uint counter)
    {
        var cred = _storeData.Credentials.First(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));
        cred.SignCount = counter;
        Sync();
    }

    public void AddCredentialToUser(Fido2User user, StoredCredential credential)
    {
        credential.UserId = user.Id;
        _storeData.Credentials.Add(credential);
        Sync();
    }

    public Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        // our in-mem storage does not allow storing multiple users for a given credentialId. Yours shouldn't either.
        var cred = _storeData.Credentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));

        if (cred is null)
            return Task.FromResult(new List<Fido2User>());

        return Task.FromResult(_storeData.Users.Where(u => u.Value.Id.SequenceEqual(cred.UserId)).Select(u => u.Value).ToList());
    }
}
