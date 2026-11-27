using System.Text;
using ClaudeDesktopGuardian.Core;

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

return await GuardianCliRunner.RunAsync(args);
