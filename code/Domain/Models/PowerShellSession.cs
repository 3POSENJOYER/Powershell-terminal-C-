using PowerShellTerminal.Domain.Prototype;

namespace PowerShellTerminal.Domain.Models
{
    public class PowerShellSession : IPrototype
    {
        public string SessionId { get; set; }
        public Dictionary<string, string> Variables { get; set; } = new();
        public Dictionary<string, string> Environment { get; set; } = new();

        public IPrototype Clone()
        {
            return new PowerShellSession
            {
                SessionId = Guid.NewGuid().ToString(),
                Variables = new Dictionary<string, string>(this.Variables),
                Environment = new Dictionary<string, string>(this.Environment)
            };
        }
    }
}
