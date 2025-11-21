namespace PowerShellTerminal.Domain.Entities
{
    public class TerminalSession
    {
        public int Id { get; set; }

        public string SessionName { get; set; } = "Default Session";
        public DateTime StartedAt { get; set; } = DateTime.UtcNow;
        public DateTime? EndedAt { get; set; }
        public bool IsActive { get; set; } = true;

        public string InitialDirectory { get; set; } = "";
    }
}
