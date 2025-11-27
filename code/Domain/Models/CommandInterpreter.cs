using System;
using System.Threading.Tasks;

namespace PowerShellTerminal.Domain.Models
{
    public class CommandInterpreter
    {
        public async Task<string> ExecuteCommand(string command)
        {
            var result = await CommandExecutor.ExecutePowerShellAsync(command);
            
            if (!string.IsNullOrEmpty(result.Errors))
            {
                return string.IsNullOrEmpty(result.Output)
                    ? $"Error: {result.Errors}"
                    : $"{result.Output}\nError: {result.Errors}";
            }

            return string.IsNullOrEmpty(result.Output) ? "Command executed successfully." : result.Output.Trim();
        }
    }
}