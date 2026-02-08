using System;

namespace TodoExample
{
    public class FailExample
    {
        // TODO: refactor this method
        public void ProcessData(string input)
        {
            var result = input.Trim();
        }

        /* FIXME: handle edge case */
        public int Calculate(int x, int y)
        {
            return x + y;
        }

        // HACK: temporary workaround for issue #123
        public string Format(string value)
        {
            return value.ToUpper();
        }

        // XXX: this needs review before release
        public void Cleanup()
        {
            GC.Collect();
        }
    }
}
