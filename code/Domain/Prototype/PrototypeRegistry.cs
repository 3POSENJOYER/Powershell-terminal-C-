using System;
using System.Collections.Generic;

namespace PowerShellTerminal.Domain.Prototype
{
    public class PrototypeRegistry
    {
        private readonly Dictionary<string, IPrototype> _prototypes = new();

        // Register a prototype by name so it can be cloned later.
        public void RegisterPrototype(string name, IPrototype proto)
        {
            if (string.IsNullOrEmpty(name)) return;
            _prototypes[name] = proto;
        }

        // Get a cloned copy of a registered prototype by name.
        public IPrototype GetPrototype(string name)
        {
            if (string.IsNullOrEmpty(name) || !_prototypes.ContainsKey(name))
                return null;
            return _prototypes[name].Clone();
        }
    }
}
