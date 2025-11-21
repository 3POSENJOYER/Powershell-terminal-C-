namespace PowerShellTerminal.Domain.Entities
{
    public class CommandHistory
    {
        public int Id { get; set; }

      
        public string Command { get; set; } = string.Empty;

       
        public string Output { get; set; } = string.Empty;

        
        public string Errors { get; set; } = string.Empty;

      
        public bool Success { get; set; }

     
        public string WorkingDirectory { get; set; } = string.Empty;

        
        public int SessionId { get; set; }

        
        public DateTime ExecutedAt { get; set; } = DateTime.Now;
    }
}
