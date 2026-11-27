using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace ClaudeDesktopGuardian.Core;

public sealed class PipeTokenStore
{
    private static readonly ConcurrentDictionary<string, string> MemoryCache = new(StringComparer.OrdinalIgnoreCase);

    private readonly string _path;

    public PipeTokenStore(string? path = null)
    {
        _path = Path.GetFullPath(path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian",
            "pipe.token"));
    }

    public string TokenPath => _path;

    public void InvalidateCache() => MemoryCache.TryRemove(_path, out _);

    public string GetOrCreate()
    {
        if (MemoryCache.TryGetValue(_path, out var cached) && !string.IsNullOrEmpty(cached))
        {
            return cached;
        }

        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Retry loop resolves cold-start race when App and Helper start simultaneously
        for (var attempt = 0; attempt < 6; attempt++)
        {
            var existing = TryReadToken();
            if (!string.IsNullOrEmpty(existing))
            {
                MemoryCache[_path] = existing;
                return existing;
            }

            var generated = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            try
            {
                using (var fs = new FileStream(_path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(fs, new UTF8Encoding(false)))
                {
                    writer.Write(generated);
                    writer.Flush();
                }

                TryApplyOwnerOnlyAcl(_path);
                MemoryCache[_path] = generated;
                return generated;
            }
            catch (IOException)
            {
                // Another process/thread created the file first; back off briefly and read it
                Thread.Sleep(25 * (attempt + 1));
            }
        }

        var finalRead = TryReadToken();
        if (!string.IsNullOrEmpty(finalRead))
        {
            MemoryCache[_path] = finalRead;
            return finalRead;
        }

        throw new IOException($"无法读取或创建管理员助手认证令牌：{_path}");
    }

    private string? TryReadToken()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            using var fs = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs, Encoding.UTF8);
            var token = reader.ReadToEnd().Trim();
            return string.IsNullOrWhiteSpace(token) ? null : token;
        }
        catch
        {
            return null;
        }
    }

    private static void TryApplyOwnerOnlyAcl(string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var currentUser = WindowsIdentity.GetCurrent().User;
            if (currentUser is not null)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    currentUser,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));
            }

            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            new FileInfo(filePath).SetAccessControl(security);
        }
        catch
        {
        }
    }
}
