namespace PowerShellTerminal.Domain.Prototype
{
    public class PrototypeRegistry
    {
        private readonly Dictionary<string, IPrototype> prototypes = new();

        public void RegisterPrototype(string name, IPrototype proto)
        {
            prototypes[name] = proto;
        }

        public IPrototype GetPrototype(string name)
        {
            return prototypes[name].Clone();
        }
    }
}
