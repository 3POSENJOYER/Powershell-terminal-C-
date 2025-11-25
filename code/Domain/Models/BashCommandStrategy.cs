using System.Diagnostics;
using System.Threading.Tasks;

namespace PowerShellTerminal.Domain.Models
{
    public class BashCommandStrategy : ICommandStrategy
    {
        public async Task<CommandResult> ExecuteAsync(string command)
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
                result.Output = await process.StandardOutput.ReadToEndAsync();
                result.Errors = await process.StandardError.ReadToEndAsync();
            }
            catch (Exception ex)
            {
                result.Errors = ex.Message;
            }

            return result;
        }
    }
}
