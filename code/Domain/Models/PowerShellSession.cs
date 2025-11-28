using System;
using System.Collections.Generic;

namespace PowerShellTerminal.Domain.Models
{
    public class PowerShellSession
    {
        public string SessionId { get; set; }
        public Dictionary<string, string> Variables { get; set; } = new Dictionary<string, string>();
        public Dictionary<string, string> Environment { get; set; } = new Dictionary<string, string>();

        public PowerShellSession CloneSession()
        {
            return new PowerShellSession
            {
                SessionId = Guid.NewGuid().ToString(),
                Variables = new Dictionary<string, string>(Variables),
                Environment = new Dictionary<string, string>(Environment)
            };
        }
    }
}
