namespace RobotRules.Exception
{
    /// <summary>
    ///   The exception that thrown when html content is empty
    /// </summary>
    public class HtmlContentEmptyException : RobotException
    {
        public HtmlContentEmptyException()
        {
        }

        public HtmlContentEmptyException(string message)
            : base(message)
        {
        }

        public HtmlContentEmptyException(string message, System.Exception inner)
            : base(message, inner)
        {
        }
    }
}