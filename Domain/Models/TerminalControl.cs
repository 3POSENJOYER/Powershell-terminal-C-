public class TerminalControl
{
    public string GetText() => "";
    public void SetBackgroundColor() { }
    public void SetForegroundColor() { }
    public void SetFont() { }
    public event EventHandler CommandEntered;
    public void WriteLine(string text) { }
    public void Clear() { }
    public Control AsControl() => null;
}