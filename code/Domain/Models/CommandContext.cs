namespace PowerShellTerminal.Domain.Models
{
    public class CommandContext
    {
        public string CurrentDirectory { get; set; } = Directory.GetCurrentDirectory();
        public Dictionary<string, string> EnvironmentVars { get; set; } = new();
        public List<string> History { get; set; } = new();

        public void SetOutput(string output)
        {
            History.Add(output);
        }
    }
}
