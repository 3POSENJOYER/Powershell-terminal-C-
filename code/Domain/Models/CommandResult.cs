namespace PowerShellTerminal.Domain.Models
{
    public class CommandResult
    {
        public string Output { get; set; }
        public string Errors { get; set; }
        public bool Success => string.IsNullOrEmpty(Errors);
    }
}
