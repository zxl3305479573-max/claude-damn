using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

/// <summary>
/// Encrypts and decrypts .csnap account snapshots using the exact format compatible with claude-switcher:
/// Header: "CSNAP001" (8B) | Salt (16B) | IV (16B) | HMAC-SHA256 (32B) | AES-256-CBC ciphertext
/// KDF: PBKDF2-HMAC-SHA256, 200,000 iterations -> 32B AES key + 32B HMAC key.
/// Encrypt-then-MAC over Header[0..40] || Ciphertext, verified in constant time before decryption.
/// </summary>
public static class EncryptedSnapshotService
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("CSNAP001");
    private const int SaltLength = 16;
    private const int IvLength = 16;
    private const int MacLength = 32;
    private const int HeaderLength = 8 + SaltLength + IvLength + MacLength; // 72 bytes
    private const int Pbkdf2Iterations = 200_000;
    private const string MetadataFileName = ".claude-switcher-snapshot.json";

    public static void ProtectFile(string plainZipPath, string destinationPath, string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 8)
        {
            throw new ArgumentException("快照密码至少需要 8 位");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var iv = RandomNumberGenerator.GetBytes(IvLength);
        var (encKey, macKey) = DeriveKeys(password, salt);

        try
        {
            using (var input = File.OpenRead(plainZipPath))
            using (var output = File.Open(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                output.Write(Magic);
                output.Write(salt);
                output.Write(iv);
                output.Write(new byte[MacLength]); // placeholder

                using var aes = Aes.Create();
                aes.KeySize = 256;
                aes.Key = encKey;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
                input.CopyTo(crypto);
            }

            var mac = ComputeMac(destinationPath, macKey);
            using (var output = File.Open(destinationPath, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                output.Position = 40;
                output.Write(mac);
                output.Flush();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    public static bool UnprotectFile(string encryptedPath, string plainZipPath, string password)
    {
        if (string.IsNullOrEmpty(password) || !File.Exists(encryptedPath))
        {
            return false;
        }

        byte[] salt;
        byte[] iv;
        byte[] expectedMac;
        using (var stream = File.Open(encryptedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (stream.Length < HeaderLength + 1)
            {
                return false;
            }

            var header = new byte[HeaderLength];
            var readTotal = 0;
            while (readTotal < HeaderLength)
            {
                var read = stream.Read(header, readTotal, HeaderLength - readTotal);
                if (read <= 0)
                {
                    return false;
                }
                readTotal += read;
            }

            if (!header.AsSpan(0, 8).SequenceEqual(Magic))
            {
                return false;
            }

            salt = header[8..24];
            iv = header[24..40];
            expectedMac = header[40..72];
        }

        var (encKey, macKey) = DeriveKeys(password, salt);
        try
        {
            var actualMac = ComputeMac(encryptedPath, macKey);
            if (!CryptographicOperations.FixedTimeEquals(actualMac, expectedMac))
            {
                return false;
            }

            using var input = File.OpenRead(encryptedPath);
            using var output = File.Open(plainZipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            input.Position = HeaderLength;

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = encKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var crypto = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
            crypto.CopyTo(output);
            return true;
        }
        catch
        {
            try { File.Delete(plainZipPath); } catch { }
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    public static void CreateNormalizedZip(string sourceDir, string zipPath, string slot)
    {
        var fullRoot = Path.GetFullPath(sourceDir).TrimEnd('\\', '/');
        using var stream = File.Open(zipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Create);

        foreach (var dir in Directory.EnumerateDirectories(fullRoot, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
            {
                continue;
            }

            var rel = dir[(fullRoot.Length + 1)..].Replace('\\', '/') + "/";
            zip.CreateEntry(rel);
        }

        foreach (var file in Directory.EnumerateFiles(fullRoot, "*", SearchOption.AllDirectories))
        {
            var attrs = File.GetAttributes(file);
            if ((attrs & FileAttributes.ReparsePoint) != 0)
            {
                continue;
            }

            var rel = file[(fullRoot.Length + 1)..].Replace('\\', '/');
            var entry = zip.CreateEntry(rel, CompressionLevel.Optimal);
            entry.ExternalAttributes = (int)attrs;
            using var entryStream = entry.Open();
            using var fileStream = File.OpenRead(file);
            fileStream.CopyTo(entryStream);
        }

        // Embed compatible metadata marker
        var metaEntry = zip.CreateEntry(MetadataFileName, CompressionLevel.Optimal);
        using var metaStream = metaEntry.Open();
        var metaPayload = JsonSerializer.Serialize(new
        {
            format = "claude-switcher-snapshot",
            version = 1,
            account = slot,
            created = DateTimeOffset.UtcNow.ToString("o"),
            platform = "Windows"
        });
        var metaBytes = Encoding.UTF8.GetBytes(metaPayload);
        metaStream.Write(metaBytes);
    }

    public static void ValidateSnapshotArchive(string zipPath, string expectedSlot)
    {
        using var stream = File.OpenRead(zipPath);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ZipArchiveEntry? marker = null;

        foreach (var entry in zip.Entries)
        {
            var name = entry.FullName;
            if (string.IsNullOrEmpty(name) ||
                name.Contains('\\') ||
                name.Contains(':') ||
                Path.IsPathRooted(name) ||
                name.StartsWith('/') ||
                Regex.IsMatch(name, @"^[A-Za-z]:"))
            {
                throw new InvalidDataException($"快照包含非法路径：{name}");
            }

            if (name.Split('/').Contains(".."))
            {
                throw new InvalidDataException($"快照包含越界路径：{name}");
            }

            var unixMode = ((uint)entry.ExternalAttributes >> 16) & 0xF000;
            if (unixMode == 0xA000)
            {
                throw new InvalidDataException($"快照包含符号链接：{name}");
            }

            if (!seen.Add(name))
            {
                throw new InvalidDataException($"快照包含重复条目：{name}");
            }

            if (name == MetadataFileName)
            {
                marker = entry;
            }
        }

        if (marker is null || marker.Length > 16384)
        {
            throw new InvalidDataException("缺少快照元数据文件或元数据过大");
        }

        using var reader = new StreamReader(marker.Open(), Encoding.UTF8);
        using var doc = JsonDocument.Parse(reader.ReadToEnd());
        var root = doc.RootElement;
        var format = root.TryGetProperty("format", out var f) ? f.GetString() : null;
        var version = root.TryGetProperty("version", out var v) && v.TryGetInt32(out var ver) ? ver : 0;
        var account = root.TryGetProperty("account", out var a) ? a.GetString() : null;
        if (format != "claude-switcher-snapshot" || version != 1)
        {
            throw new InvalidDataException("快照格式不受支持");
        }

        if (string.IsNullOrEmpty(account) || !Regex.IsMatch(account, "^[A-D]$") ||
            !string.Equals(account, expectedSlot, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"快照账号槽位不匹配（快照为 {account ?? "未知"}，目标为 {expectedSlot}）");
        }
    }

    private const int MaxArchiveEntries = 100_000;
    private const long MaxUncompressedBytes = 4L * 1024 * 1024 * 1024; // 4 GiB

    public static void ExtractSnapshotArchive(string zipPath, string destinationDir)
    {
        var fullRoot = Path.GetFullPath(destinationDir);
        Directory.CreateDirectory(fullRoot);
        var rootPrefix = fullRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

        using var stream = File.OpenRead(zipPath);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        if (zip.Entries.Count > MaxArchiveEntries)
        {
            throw new InvalidDataException($"快照条目数超限（>{MaxArchiveEntries}）");
        }

        long totalBytes = 0;
        var buffer = new byte[81920];
        foreach (var entry in zip.Entries)
        {
            if (string.Equals(entry.FullName, MetadataFileName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
            var targetPath = Path.GetFullPath(Path.Combine(fullRoot, relative));
            if (!targetPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"快照解压目标越界：{entry.FullName}");
            }

            if (entry.FullName.EndsWith('/'))
            {
                Directory.CreateDirectory(targetPath);
                continue;
            }

            var parent = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrWhiteSpace(parent))
            {
                Directory.CreateDirectory(parent);
            }

            using var entryStream = entry.Open();
            using var outputStream = File.Open(targetPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            int read;
            while ((read = entryStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                totalBytes += read;
                if (totalBytes > MaxUncompressedBytes)
                {
                    throw new InvalidDataException("快照解压体积超过安全上限（4 GiB）");
                }

                outputStream.Write(buffer, 0, read);
            }
        }
    }

    private static (byte[] EncryptionKey, byte[] MacKey) DeriveKeys(string password, byte[] salt)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            var material = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 64);
            var encKey = material[..32];
            var macKey = material[32..64];
            CryptographicOperations.ZeroMemory(material);
            return (encKey, macKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] ComputeMac(string path, byte[] macKey)
    {
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var hmac = new HMACSHA256(macKey);

        var headerPrefix = new byte[40];
        var readTotal = 0;
        while (readTotal < 40)
        {
            var read = stream.Read(headerPrefix, readTotal, 40 - readTotal);
            if (read <= 0)
            {
                throw new InvalidDataException("快照文件头不完整");
            }
            readTotal += read;
        }

        hmac.TransformBlock(headerPrefix, 0, headerPrefix.Length, headerPrefix, 0);
        stream.Position = HeaderLength;

        var buffer = new byte[1024 * 1024];
        int readBytes;
        while ((readBytes = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hmac.TransformBlock(buffer, 0, readBytes, buffer, 0);
        }

        hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return hmac.Hash ?? Array.Empty<byte>();
    }
}
