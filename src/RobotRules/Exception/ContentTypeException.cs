namespace BlueCurve.Search.RobotRules.Exception
{
    /// <summary>
    ///   The exception that is thrown when a robot control file has an inappropriate content type.
    /// </summary>
    public class ContentTypeException : RobotException
    {
        private const string DefaultMessage = "The content type is not valid.";


        public ContentTypeException(string contentType)
            : base(DefaultMessage)
        {
            ContentType = contentType;
        }

        public ContentTypeException(string contentType, System.Exception inner)
            : base(DefaultMessage, inner)
        {
            ContentType = contentType;
        }

        public ContentTypeException(string message, string contentType)
            : base(message)
        {
            ContentType = contentType;
        }

        public ContentTypeException(string message, string contentType, System.Exception inner)
            : base(message, inner)
        {
            ContentType = contentType;
        }

        public string ContentType { get; private set; }
    }
}