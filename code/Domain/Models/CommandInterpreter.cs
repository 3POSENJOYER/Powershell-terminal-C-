using System.Diagnostics;

namespace PowerShellTerminal.Domain.Models
{
    public class CommandInterpreter
    {
        public async Task<string> ExecuteCommand(string command)
        {
            try
            {
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{EscapeCommand(command)}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8,
                    StandardErrorEncoding = System.Text.Encoding.UTF8
                };

                using var process = new Process();
                process.StartInfo = processStartInfo;
                
                Console.WriteLine($"Executing: {command}");
                
                process.Start();
                
                string output = await process.StandardOutput.ReadToEndAsync();
                string error = await process.StandardError.ReadToEndAsync();
                
                await process.WaitForExitAsync();
                
                if (!string.IsNullOrEmpty(error))
                {
                    if (!string.IsNullOrEmpty(output))
                        output += Environment.NewLine + "Error: " + error;
                    else
                        output = "Error: " + error;
                }

                return string.IsNullOrEmpty(output) ? "Command executed successfully." : output.Trim();
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }
        }

        private string EscapeCommand(string command)
        {
            return command.Replace("\"", "\\\"")
                         .Replace("`", "``")
                         .Replace("$", "`$");
        }
    }
}