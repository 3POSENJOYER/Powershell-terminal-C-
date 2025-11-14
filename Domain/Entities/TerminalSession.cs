public class TerminalSession
{
    public int Id { get; set; }
    public string SessionName { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime? EndedAt { get; set; }
    public string InitialDirectory { get; set; }
    public bool IsActive { get; set; }
}