using System.Security.Cryptography;

namespace ClaudeDesktopGuardian.Core;

public sealed class PipeTokenStore
{
    private readonly string _path;

    public PipeTokenStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian",
            "pipe.token");
    }

    public string GetOrCreate()
    {
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (File.Exists(_path))
        {
            return File.ReadAllText(_path).Trim();
        }

        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        File.WriteAllText(_path, token);
        return token;
    }
}

