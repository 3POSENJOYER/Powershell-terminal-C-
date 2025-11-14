public class CommandHistory
{
    public int Id { get; set; }
    public string Command { get; set; }
    public string Output { get; set; }
    public string Errors { get; set; }
    public bool Success { get; set; }
    public DateTime ExecutedAt { get; set; }
    public string WorkingDirectory { get; set; }
    public int SessionId { get; set; }
}