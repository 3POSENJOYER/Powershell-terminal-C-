public class TerminalTab
{
    public TerminalControl TerminalControl { get; set; }
    public CommandInterpreter Interpreter { get; set; }
    public TabPage TabPage { get; set; }

    public void ApplyTheme() { }
    public void SetFocus() { }
}