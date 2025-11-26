using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace PowerShellTerminal.Domain.Models
{
    /// <summary>
    /// Utility class for executing commands in different shells.
    /// Replaces the Strategy pattern with simple static methods.
    /// </summary>
    public static class CommandExecutor
    {
        /// <summary>Execute a PowerShell command.</summary>
        public static async Task<CommandResult> ExecutePowerShellAsync(string command)
        {
            var result = new CommandResult();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    result.Output = await process.StandardOutput.ReadToEndAsync();
                    result.Errors = await process.StandardError.ReadToEndAsync();
                }
            }
            catch (Exception ex)
            {
                result.Errors = ex.Message;
            }
            return result;
        }

        /// <summary>Execute a cmd command.</summary>
        public static async Task<CommandResult> ExecuteCmdAsync(string command)
        {
            var result = new CommandResult();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/C {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    result.Output = await process.StandardOutput.ReadToEndAsync();
                    result.Errors = await process.StandardError.ReadToEndAsync();
                }
            }
            catch (Exception ex)
            {
                result.Errors = ex.Message;
            }
            return result;
        }

        /// <summary>Execute a bash command.</summary>
        public static async Task<CommandResult> ExecuteBashAsync(string command)
        {
            var result = new CommandResult();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "bash",
                    Arguments = $"-c \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    result.Output = await process.StandardOutput.ReadToEndAsync();
                    result.Errors = await process.StandardError.ReadToEndAsync();
                }
            }
            catch (Exception ex)
            {
                result.Errors = ex.Message;
            }
            return result;
        }
    }
}
