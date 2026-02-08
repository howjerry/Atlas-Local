using System;

namespace ObjectTypeExample
{
    public class FailExample
    {
        public void Process(object data)
        {
            Console.WriteLine(data.ToString());
        }

        public void Handle(object input, object output)
        {
            var result = input.ToString() + output.ToString();
        }

        public string Serialize(object value)
        {
            return value.ToString();
        }
    }
}
