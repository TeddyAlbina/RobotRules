namespace BlueCurve.Search.RobotRules.Exception
{
    /// <summary>
    ///   The exception that is thrown when an error occurs parsing html tag "robot"
    /// </summary>
    public class HtmlMetaParseException : RobotException
    {
        public HtmlMetaParseException()
        {
        }

        public HtmlMetaParseException(string message)
            : base(message)
        {
        }

        public HtmlMetaParseException(string message, System.Exception inner)
            : base(message, inner)
        {
        }
    }
}