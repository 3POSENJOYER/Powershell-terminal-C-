public class CommandResult
{
    public string Output { get; set; } = string.Empty;
    public string Errors { get; set; } = string.Empty;
    public bool Success { get; set; }
    
    public static CommandResult Empty => new CommandResult();
}