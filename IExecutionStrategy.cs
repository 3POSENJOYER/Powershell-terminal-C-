using System.Threading.Tasks;

public interface IExecutionStrategy
{
    Task<CommandResult> ExecuteAsync(string command);
    bool CanExecute(string command);
}

public class PowerShellExecutionStrategy : IExecutionStrategy
{
    public async Task<CommandResult> ExecuteAsync(string command)
    {
        try
        {
            var processStartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-Command \"{command}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            using var process = new System.Diagnostics.Process { StartInfo = processStartInfo };
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
        catch (System.Exception ex)
        {
            return new CommandResult
            {
                Errors = $"Error: {ex.Message}",
                Success = false
            };
        }
    }
    
    public bool CanExecute(string command) => true;
}

public class ExecutableExecutionStrategy : IExecutionStrategy
{
    public async Task<CommandResult> ExecuteAsync(string command)
    {
        try
        {
            var processStartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            using var process = new System.Diagnostics.Process { StartInfo = processStartInfo };
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
        catch (System.Exception ex)
        {
            return new CommandResult
            {
                Errors = $"Error: {ex.Message}",
                Success = false
            };
        }
    }
    
    public bool CanExecute(string command) => 
        System.IO.File.Exists(command.Split(' ')[0]) || command.StartsWith(".\\");
}