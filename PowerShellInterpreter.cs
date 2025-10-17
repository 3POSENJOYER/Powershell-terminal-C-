using System;
using System.Diagnostics;
using System.Threading.Tasks;

public class PowerShellInterpreter
{
    public async Task<CommandResult> InterpretAsync(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return CommandResult.Empty;

        try
        {
            var processStartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-Command \"{input}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            using var process = new Process { StartInfo = processStartInfo };
            process.Start();
            
            var output = await process.StandardOutput.ReadToEndAsync();
            var errors = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            
            return new CommandResult
            {
                Output = output,
                Errors = errors,
                Success = process.ExitCode == 0
            };
        }
        catch (Exception ex)
        {
            return new CommandResult
            {
                Errors = $"Error: {ex.Message}",
                Success = false
            };
        }
    }
}