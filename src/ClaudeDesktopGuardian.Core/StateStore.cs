using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

public sealed class GuardianStateStore
{
    private static readonly Regex IpPattern = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);
    private readonly string _path;

    public GuardianStateStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian",
            "state.json");
    }

    public GuardianState Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new GuardianState(false, string.Empty, null, null);
            }

            var state = JsonSerializer.Deserialize<GuardianState>(
                File.ReadAllText(_path));
            return state ?? new GuardianState(false, string.Empty, null, null);
        }
        catch
        {
            return new GuardianState(false, "状态文件无法读取", null, null);
        }
    }

    public void Save(GuardianState state)
    {
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporary = _path + ".tmp";
        var safe = state with
        {
            TripReason = state.Blocked ? Sanitize(state.TripReason) : string.Empty,
            BlockedAt = state.Blocked ? state.BlockedAt : null
        };
        File.WriteAllText(temporary, JsonSerializer.Serialize(safe, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        File.Move(temporary, _path, true);
    }

    private static string Sanitize(string text) => IpPattern.Replace(text, "<IP>");
}

