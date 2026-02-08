using System;

namespace ObjectTypeExample
{
    public interface IProcessable
    {
        string Process();
    }

    public class PassExample
    {
        public void Process<T>(T data) where T : IProcessable
        {
            Console.WriteLine(data.Process());
        }

        public void Handle(string input)
        {
            Console.WriteLine(input);
        }

        public string Serialize(int value)
        {
            return value.ToString();
        }
    }
}
