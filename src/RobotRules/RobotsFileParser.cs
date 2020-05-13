using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using BlueCurve.Search.RobotRules.Abstractions;
using BlueCurve.Search.RobotRules.Exception;
using HtmlAgilityPack;

namespace BlueCurve.Search.RobotRules
{
    /// <summary>
    ///   Parses robot control files and indicates which resources are accessible to named user agents.
    /// </summary>
    /// <remarks>
    ///   Based on Martijn Koster's 1996 RFC Draft Memo on Web Robots Control, with optional support for the blank Disallow lines of 'A Standard for Robot Exclusion' (1994). At the time of writing (2005), the 1994 document is still current, but the 1996 document is essentially backwards-compatible.
    /// </remarks>
    public sealed class RobotsFileParser : IRobotFileParser
    {
        /// <summary>
        ///   The filename used for robot control files.
        /// </summary>
        public const string RobotsFileName = "robots.txt";


        /// <summary>
        ///   The user agent token that represents all user agents.
        /// </summary>
        public const string TokenAllUserAgents = "*";


        /// <summary>
        ///   The content type used for robot control files.
        /// </summary>
        private const string RobotsContentType = "text/plain";


        /// <summary>
        ///   The set of characters (excluding control characters, i.e. those whose ASCII value is lower than 0x20, space) that are not permitted in a token, as defined in RFC 1945.
        /// </summary>
        private const string Rfc1945InvalidChars = "()<>@,;:\"\\/[]?={} ";


        /// <summary>
        ///   The set of characters (excluding '%', which is only valid as part of a hex triplet) that are permitted in a "pchar", as defined by RFC 1808.
        /// </summary>
        /// <remarks>
        ///   This includes digits, alphabetic characters (regardless of case), "safe" characters <![CDATA[
        /// ('$', '-', '_', '.', '+'), "extra" characters ('!', '*', "'", '(', ')', ','),
        /// "national" characters ('{', '}', '|', '\', '^', '~', '[', ']', '`'), and the
        /// other characters that are specifically allowed in "pchar" (':', '@', '&', '=').
        /// ]]>
        /// </remarks>
        private const string Rfc1808SinglePchars
            = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
              + "$-_.+!*'(),{}|\\^~[]`:@&=";

        private static readonly Regex ExtensionLineRegex = new Regex(@"^.+:\s*.+", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private readonly ConcurrentDictionary<string, Rule[]> rulesForUserAgents = new ConcurrentDictionary<string, Rule[]>(StringComparer.InvariantCultureIgnoreCase);

        /// <summary>
        ///   Data access layer object
        /// </summary>
        private readonly IRobotRulesCache? robotRulesCache;

        /// <summary>
        /// Initializes a new instance of the <see cref="RobotsFileParser"/> class.
        /// </summary>
        /// <param name="robotRulesCache">The robot rules cache.</param>
        public RobotsFileParser([DisallowNull] IRobotRulesCache robotRulesCache)
        {
            this.Options = ParseOptions.Defaults;

            this.robotRulesCache = robotRulesCache;

            this.Clear();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RobotsFileParser"/> class.
        /// </summary>
        public RobotsFileParser()
        {

        }


        /// <summary>
        ///   Reads and interprets the contents of a Web site's robot control file.
        /// </summary>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        public RobotsFileParser(Uri site)
            : this()
        {
            this.Parse(site);
        }


        /// <summary>
        ///   Reads and interprets the contents of a Web site's robot control file.
        /// </summary>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        /// <param name="timeout"> The time, in milliseconds, after which the Web request should be aborted if no response has been received, or zero for the default timeout. </param>
        public RobotsFileParser(Uri site, int timeout)
            : this()
        {
            this.Parse(site, timeout);
        }


        /// <summary>
        ///   Reads and interprets the contents of a robot control file.
        /// </summary>
        /// <param name="file"> The robot control file. </param>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        public RobotsFileParser(FileInfo file, Uri site)
            : this()
        {
            this.Parse(file, site);
        }


        /// <summary>
        ///   Reads and interprets the contents of a robot control file.
        /// </summary>
        /// <param name="robotsFileLines"> The lines of the file in sequential order. </param>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        public RobotsFileParser(string[] robotsFileLines, Uri site)
            : this()
        {
            this.Parse(robotsFileLines, site);
        }

        /// <summary>
        ///   Gets or sets a value indicating how robot control files should be parsed.
        /// </summary>
        public ParseOptions Options { get; set; }


        /// <summary>
        ///   Gets a value indicating whether access to the current site is completely forbidden because access to the robot control file was forbidden.
        /// </summary>
        public bool AllRestricted { get; private set; }


        /// <summary>
        ///   Gets the URI of the Web site whose robot control file has been parsed.
        /// </summary>
        /// <remarks>
        ///   The URI includes the scheme and authority but no path segments. This would usually correspond to the Web site's home page.
        /// </remarks>
        public Uri? SiteBase { get; private set; }

        /// <summary>
        ///   User agent for download robots file
        /// </summary>
        public string? LocalUserAgent { get; set; }


        // Methods

        /// <summary>
        ///   Resets the parser to its original empty state.
        /// </summary>
        public void Clear()
        {
            this.rulesForUserAgents.Clear();
            this.SiteBase = null;
            this.AllRestricted = false;
        }


        /// <summary>
        ///   Returns the regular expression options to be used when validating a field name in a robot control file.
        /// </summary>
        /// <returns> The regular expression options to be used. </returns>
        private RegexOptions GetRegexOptions()
            => ((this.Options & ParseOptions.IgnoreFieldNameCase) != 0)
            ? RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled
            : RegexOptions.CultureInvariant | RegexOptions.Compiled;

        /// <summary>
        ///   Determines whether a normalised line from a robot control file is a User-agent line.
        /// </summary>
        /// <param name="line"> The line. </param>
        /// <param name="userAgent"> The user agent string, or null. </param>
        /// <returns> True if the line is a User-agent line, else false. </returns>

        private bool IsUserAgentLine(string line, [MaybeNullWhen(false)] out string? userAgent)
        {
            userAgent = null;

            if (Regex.IsMatch(line, @"^User-agent:\s*.+", this.GetRegexOptions()))
            {
                userAgent = line.Substring("User-agent:".Length).Trim();

                // The user agent must be an RFC 1945 token, but to be permissive in reading
                // we will try to truncate it to a valid token if it is not entirely valid.

                int tokenLength = this.GetRfc1945TokenValidLength(userAgent);

                // entirely valid, or can be truncated to be valid
                if (tokenLength > 0)
                {
                    userAgent = userAgent.Substring(0, tokenLength);
                }
            }

            return (userAgent != null);
        }


        /// <summary>
        ///   Determines whether a normalised line from a robot control file is an Allow or Disallow line with at least one valid path.
        /// </summary>
        /// <param name="line"> The line. </param>
        /// <param name="allow"> Whether the line is an Allow line. </param>
        /// <param name="paths"> The valid paths to which the rule refers, or null. </param>
        /// <returns> True if the line is an Allow or Disallow line, else false. </returns>
        private bool IsAllowOrDisallowLine(string line, out bool allow, [MaybeNullWhen(false)] out string[] paths)
        {
            paths = null;
            allow = false;

            // Handle the blank Disallow line (1994 spec)

            if ((this.Options | ParseOptions.AcceptBlankDisallow) != 0 && Regex.IsMatch(line, "^Disallow:$", this.GetRegexOptions()))
            {
                line = "Allow: /"; // allowing everything (1996 spec) is disallowing nothing (1994)
            }

            // Now check the line properly

            if (Regex.IsMatch(line, @"^Allow:\s*.+", this.GetRegexOptions()))
            {
                paths = line.Substring("Allow:".Length).Trim().Split(null);
                allow = true;
            }
            else if (Regex.IsMatch(line, @"^Disallow:\s*.+", this.GetRegexOptions()))
            {
                paths = line.Substring("Disallow:".Length).Trim().Split(null);
            }

            if (paths != null) // found a path, or several (delimited by whitespace)
            {
                var validPaths = new List<string>(paths);

                for (int i = 0; i < validPaths.Count; i++)
                {
                    // Add leading '/' if not present. (Section 3.3 of the robot control
                    // standard insists on a leading '/' for Allow rules, but we always want
                    // to store one anyway and it's good to be permissive in what we read.)

                    if (!validPaths[i].StartsWith("/"))
                    {
                        validPaths[i] = "/" + (string)validPaths[i];
                    }

                    // Discard the path if it isn't valid

                    if (!this.IsValidPathForRule((string)validPaths[i], allow))
                    {
                        validPaths.RemoveAt(i);
                        i--;
                    }
                }

                paths = null;

                if (validPaths.Count > 0) // repopulate the array with only the valid ones
                {
                    paths = validPaths.ToArray();
                }
            }

            return (paths != null);
        }


        /// <summary>
        ///   Determines whether a URI contains any incorrectly formed hexadecimal character escape.
        /// </summary>
        /// <param name="uri"> The URI to be tested. </param>
        /// <returns> True if the URI contains any incorrectly formed character escape. </returns>
        private static bool ContainsInvalidCharEscapes(string? uri)
        {
            int pos = 0;

            if (uri != null)
            {
                if (uri.Length > 2 && uri.LastIndexOf("%", StringComparison.Ordinal) > uri.Length - 3)
                {
                    return true; // % not followed by two characters
                }

                while ((pos = uri.IndexOf("%", pos, System.StringComparison.Ordinal)) >= 0)
                {
                    string digits = uri.Substring(pos + 1, 2); // the next two characters

                    if (!Uri.IsHexDigit(digits[0]) || !Uri.IsHexDigit(digits[1]))
                    {
                        return true; // invalid hex digit
                    }

                    pos++;
                }
            }

            return false;
        }


        /// <summary>
        ///   Determines whether a string is a suitable path for an Allow or Disallow rule.
        /// </summary>
        /// <remarks>
        ///   The path must be the leftmost non-empty part of a relative URI, considered to be rooted at the host, such as "/" or "/docum" or "/documents/" or "/~bob/index.htm". Complete URIs (with scheme and authority) such as "http:// ..." will not work; however, RFC 1808 allows ':' in path segments and permits empty path segments (so that '//' is legal), so we can't actually exclude anything that looks like a complete URI but must treat it as a relative one ("http://site.com/http://..."). Any fragment identifier ("#section") will have been removed as a comment - and is meaningless to robots anyway - so we can ignore those.
        /// </remarks>
        /// <param name="s"> The string to be tested. </param>
        /// <param name="isAllowRule"> Whether the rule is an Allow rule. </param>
        /// <returns> True if the string is a valid path, else false. </returns>
        private bool IsValidPathForRule(string s, bool isAllowRule)
        {
            bool validPath = false;

            // Allow rules must begin with '/'. This is an explicit rule in section 3.3
            // of the robot control standard: compare 'allowline' with 'disallowline'.
            // (In this library, though, the calling code prepends '/' if necessary.)

            if (!isAllowRule || s.StartsWith("/"))
            {
                if (s != "/robots.txt") // "The /robots.txt URL ... must not appear in ... rules."
                {
                    validPath = (s == "/") || this.IsRfc1808Path(s.TrimStart('/'));
                }
            }

            return validPath;
        }

        /// <summary>
        ///   Returns the number of leading characters in a string that form a valid token, as defined by RFC 1945.
        /// </summary>
        /// <param name="s"> The string to be tested. </param>
        /// <returns> The number of leading characters that form a valid token. </returns>
        private int GetRfc1945TokenValidLength(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] < ' ' || Rfc1945InvalidChars.IndexOf(s[i]) != -1)
                {
                    return i; // found the first invalid character
                }
            }

            return s.Length; // the entire string was valid, *or* the string was empty
        }

        /// <summary>
        ///   Determines whether a string is a token, as defined by RFC 1945.
        /// </summary>
        /// <param name="s"> The string to be tested. </param>
        /// <returns> True if the string is a valid token, else false. </returns>
        public bool IsRfc1945Token(string? s) => (!string.IsNullOrEmpty(s) && s.Length == this.GetRfc1945TokenValidLength(s));

        /// <summary>
        ///   Determines whether a normalised line from a robot control file matches the specification for an extension (i.e. some future addition to the format).
        /// </summary>
        /// <param name="line"> The line. </param>
        /// <returns> True if the line is an extension, else false. </returns>
        private bool IsExtensionLine(string line)
        {
            // An extension line takes the form
            // <RFC 1945 token> ':' <optional whitespace> <value>

            if (!string.IsNullOrWhiteSpace(line) && ExtensionLineRegex.IsMatch(line))
            {
                string token = line.Substring(0, line.IndexOf(':')); // everything before the colon

                if (this.IsRfc1945Token(token))
                {
                    var rhs = line.Substring(line.IndexOf(":", StringComparison.Ordinal) + 1).Trim();

                    if (rhs.Length > 0) // must be at least one character
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        ///   Converts a line from a robot control file into a normal form by removing leading and trailing whitespace and comments.
        /// </summary>
        /// <param name="line"> The line. </param>
        /// <returns> The normalized line. </returns>
        private string NormalizeLine(string line)
        {
            if (line.IndexOf("#", System.StringComparison.Ordinal) != -1) // there is a comment
            {
                line = line.Substring(0, line.IndexOf("#", System.StringComparison.Ordinal));
            }

            return line.Trim();
        }


        /// <summary>
        ///   Adds a set of rules for a set of user agents to a hashtable.
        /// </summary>
        /// <param name="userAgents"> The set of user agent tokens (ArrayList of string). </param>
        /// <param name="rules"> The set of rules (ArrayList of Rule). </param>
        private void CommitRules(IEnumerable<string> userAgents, Rule[] rules)
        {
            if (rules != null && userAgents != null)
            {
                foreach (var agent in userAgents)
                {
                    // "The robot must obey the first record in /robots.txt that contains a
                    // User-agent line whose value contains the name token of the robot as a
                    // [case-insensitive] substring."
                    // So, we'll ignore any later records for a previously-seen user agent.
                    if (!this.rulesForUserAgents.ContainsKey(agent))
                    {
                        // Add the rules for this particular user agent
                        this.rulesForUserAgents[agent] = rules;
                    }
                }
            }
        }


        /// <summary>
        ///   Determines whether a string is a valid "path", as defined by RFC 1808.
        /// </summary>
        /// <param name="s"> The string to be tested. </param>
        /// <returns> True if the string is a "path", else false. </returns>
        public bool IsRfc1808Path([DisallowNull] string s)
        {
            // The grammar tells us this:
            // path		= fsegment *( "/" segment )
            // fsegment	= 1*pchar  <-- "one or more pchar"
            // segment	= *pchar   <-- "zero or more pchar"
            // i.e. exactly one "fsegment" (first segment) followed by zero or more "segment",
            // each of the latter preceded by '/'. Since "segment" (but not "fsegment") can be empty,
            // '/' can occur anywhere (even consecutively) except the first character of the path.
            // Every other non-'/' character must be a "pchar".
            // This just leaves the question of hex escapes (%xx), each of which - despite having three
            // characters - is a valid "pchar". We'll test those at the end.

            // First, check the single characters

            if (s.Length > 0 && s[0] != '/') // first char can't be '/'
            {
                for (int i = 0; i < s.Length; i++)
                {
                    if (s[i] == '%') // start of a hex escape
                    {
                        i += 2; // next two chars should be hex digits; check them later
                    }
                    else if (s[i] != '/' && !this.IsRfc1808Pchar(s[i].ToString(CultureInfo.InvariantCulture)))
                    {
                        return false; // invalid character
                    }
                }

                // Now we just need to validate any hex escape sequences

                return !ContainsInvalidCharEscapes(s);
            }

            return false;
        }


        /// <summary>
        ///   Determines whether a string is a valid "pchar" (path character), as defined by RFC 1808.
        /// </summary>
        /// <param name="s"> The string to be tested. </param>
        /// <returns> True if the string is a "pchar", else false. </returns>
        private bool IsRfc1808Pchar([DisallowNull] string s)
        {
            if (s.Length == 1) // single character
            {
                return (Rfc1808SinglePchars.IndexOf(s, System.StringComparison.Ordinal) != -1);
            }
            if (s.Length == 3) // should be a hex escape %xx
            {
                return (s[0] == '%' && Uri.IsHexDigit(s[1]) && Uri.IsHexDigit(s[2]));
            }

            return false; // wrong length
        }


        /// <summary>
        ///   Check if robot control file has been updated since the latest download
        /// </summary>
        /// <param name="uri"> The URI of the robot control file. < </param>
        /// <param name="timeout"> The time, in milliseconds, after which the Web request should be aborted if no response has been received, or zero for the default timeout. </param>
        /// <returns> State if true the robot control file is fresh, else we need to download it. By default the function return true </returns>
        private bool IsFresh([DisallowNull] Uri uri, int timeout)
        {
            var req = (HttpWebRequest)WebRequest.Create(uri);
            req.AllowAutoRedirect = false;
            req.Method = "HEAD";

            if (!string.IsNullOrEmpty(this.LocalUserAgent) && this.LocalUserAgent != null)
            {
                req.UserAgent = this.LocalUserAgent;
            }

            if (timeout != 0)
                req.Timeout = timeout;

            try
            {
                DateTime date;
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    string contentType = resp.ContentType;

                    if (contentType.Contains(";"))
                        contentType = contentType.Split(';')[0].Trim();

                    if (!contentType.Equals(RobotsContentType, StringComparison.InvariantCultureIgnoreCase))
                    {
                        throw new ContentTypeException(
                            "The Content-Type header is not '" + RobotsContentType + "'.",
                            resp.ContentType
                            );
                    }

                    date = resp.LastModified;

                    resp.Close();
                }

                var latest = this.robotRulesCache?.GetDate(uri.OriginalString);

                if (latest == null)
                {
                    return true;
                }

                if (latest.Value != date)
                {
                    return false;
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError) // an HTTP error status code
                {
                    HttpStatusCode statusCode = ((HttpWebResponse)ex.Response).StatusCode;

                    if (statusCode == HttpStatusCode.NotFound) // 404
                    {
                        // "If the server response indicates the resource does not exist ...
                        // the robot can assume no instructions are available, and that access to
                        // the site is not restricted."
                    }
                    if (statusCode == HttpStatusCode.Unauthorized // 401
                        || statusCode == HttpStatusCode.Forbidden) // 403
                    {
                        // "On server response indicating access restrictions (HTTP Status Code 401
                        // or 403) a robot should regard access to the site completely restricted."

                        this.AllRestricted = true;
                    }
                }
                else // some genuine HTTP transmission error, such as a timeout
                {
                    // "On the request attempt resulted in temporary failure a robot should defer
                    // visits to the site until such time as the resource can be retrieved."
                    // Since this is just a parser, that's not our problem.

                    throw new DownloadFailedException(uri, ex);
                }
            }

            return true;
        }

        /// <summary>
        ///   Retrieves a robot control file from a Web server.
        /// </summary>
        /// <param name="uri"> The URI of the robot control file. </param>
        /// <param name="timeout"> The time, in milliseconds, after which the Web request should be aborted if no response has been received, or zero for the default timeout. </param>
        /// <returns> The lines from the robot control file, or an empty array if the file was not found. </returns>
        private string[] DownloadRobotControlFile([DisallowNull] Uri uri, int timeout)
        {
            var isfresh = this.IsFresh(uri, timeout);

            var isexist = this.robotRulesCache.CheckExist(uri.OriginalString);

            if (isexist && isfresh)
            {
                var file = this.robotRulesCache.GetRobotControlFile(uri.OriginalString);

                if (file != null)
                {
                    return file;
                }

                isexist = false;

                this.robotRulesCache.Delete(uri.OriginalString);
            }

            var lines = new List<string>();
            var sb = new StringBuilder();

            var req = (HttpWebRequest)WebRequest.Create(uri);

            if (!string.IsNullOrEmpty(this.LocalUserAgent) && this.LocalUserAgent != null)
            {
                req.UserAgent = this.LocalUserAgent;
            }

            if (timeout != 0)
            {
                req.Timeout = timeout;
            }

            // "On server response indicating Redirection (HTTP Status Code 3xx) a robot should
            // follow the redirects until a resource can be found." - this is dealt with already,
            // since HttpWebRequest.AllowAutoRedirect is true by default.

            try
            {
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    string contentType = resp.ContentType;

                    if (contentType.Contains(";"))
                        contentType = contentType.Split(';')[0].Trim();

                    if (!contentType.Equals(RobotsContentType, StringComparison.InvariantCultureIgnoreCase))
                    {
                        throw new ContentTypeException(
                            "The Content-Type header is not '" + RobotsContentType + "'.",
                            resp.ContentType
                            );
                    }

                    using (var reader = new StreamReader(resp.GetResponseStream()))
                    {
                        string? currentLine = null;
                        while ((currentLine = reader.ReadLine()) != null)
                        {
                            lines.Add(currentLine);
                            sb.Append(currentLine);
                        }

                        reader.Close();
                    }

                    // Add data to the database
                    if (isexist)
                    {
                        this.robotRulesCache.Update(uri.OriginalString, sb.ToString());
                    }

                    if (!isexist)
                    {
                        this.robotRulesCache.Add(uri.OriginalString, sb.ToString());
                    }

                    resp.Close();
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError) // an HTTP error status code
                {
                    var statusCode = ((HttpWebResponse)ex.Response).StatusCode;

                    if (statusCode == HttpStatusCode.NotFound) // 404
                    {
                        // "If the server response indicates the resource does not exist ...
                        // the robot can assume no instructions are available, and that access to
                        // the site is not restricted."
                    }
                    if (statusCode == HttpStatusCode.Unauthorized // 401
                        || statusCode == HttpStatusCode.Forbidden) // 403
                    {
                        // "On server response indicating access restrictions (HTTP Status Code 401
                        // or 403) a robot should regard access to the site completely restricted."

                        this.AllRestricted = true;
                    }
                }
                else // some genuine HTTP transmission error, such as a timeout
                {
                    // "On the request attempt resulted in temporary failure a robot should defer
                    // visits to the site until such time as the resource can be retrieved."
                    // Since this is just a parser, that's not our problem.

                    throw new DownloadFailedException(uri, ex);
                }
            }

            return lines.ToArray();
        }


        /// <summary>
        ///   Reads and interprets the contents of a Web site's robot control file.
        /// </summary>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        public void Parse([DisallowNull] Uri site)
        {
            this.Parse(site, 0); // default timeout
        }


        /// <summary>
        ///   Reads and interprets the contents of a Web site's robot control file. If the site has no robot control file, it is assumed that robots may access any part of the site.
        /// </summary>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        /// <param name="timeout"> The time, in milliseconds, after which the Web request should be aborted if no response has been received, or zero for the default timeout. </param>
        public void Parse([DisallowNull] Uri site, int timeout)
        {
            var robotsFile = this.GetRobotsFileUri(site);

            var content = this.DownloadRobotControlFile(robotsFile, timeout);

            this.Parse(content, site);
        }


        /// <summary>
        ///   Reads and interprets the contents of a robot control file.
        /// </summary>
        /// <param name="file"> The robot control file. </param>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        public void Parse([DisallowNull] FileInfo file, [DisallowNull] Uri site)
        {
            string filename = file.FullName;

            if (!File.Exists(filename))
            {
                throw new FileNotFoundException("The file does not exist.", filename);
            }

            var lines = new ArrayList();

            using (var reader = new StreamReader(filename))
            {
                string? currentLine = null;
                while ((currentLine = reader.ReadLine()) != null)
                {
                    lines.Add(currentLine);
                }

                reader.Close();
            }

            this.Parse((string[])lines.ToArray(typeof(string)), site);
        }


        /// <summary>
        ///   Reads and interprets the contents of a robot control file.
        /// </summary>
        /// <param name="robotsFileLines"> The lines of the file in sequential order. </param>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        public void Parse([DisallowNull] string[] robotsFileLines, [DisallowNull] Uri site)
        {
            this.Clear();

            this.SiteBase = new Uri(site.GetLeftPart(UriPartial.Authority));

            var userAgentsSoFar = new List<string>();
            var rulesSoFar = new List<Rule>();

            bool lastLineWasUserAgent = false;

            // The robot control standard describes a record as at least one user agent line
            // (perhaps with comments between them) followed by at least one rule line (ditto).
            // This doesn't seem to permit blank lines within records, so we're being permissive.
            // The standard also specifies that the entire file should be a "non-empty set of
            // records", but we won't complain if the file is empty.

            int recordIndex = 0; // zero-based index of the record (block of rules)

            for (int i = 0; i < robotsFileLines.Length; i++)
            {
                string line = this.NormalizeLine(robotsFileLines[i]);

                if (!string.IsNullOrWhiteSpace(line)) // not blank or a lone comment
                {
                    if (this.IsUserAgentLine(line, out var userAgent) && !string.IsNullOrWhiteSpace(userAgent))
                    {
                        if (!lastLineWasUserAgent && rulesSoFar.Count > 0) // end of previous block
                        {
                            // Commit the queued-up rules for the previous block

                            this.CommitRules(userAgentsSoFar, rulesSoFar.ToArray());

                            userAgentsSoFar.Clear();
                            rulesSoFar.Clear();

                            recordIndex++;

                            // If the previous block applied to all user agents,
                            // then there is no point in reading any further.

                            if (userAgentsSoFar.Contains(TokenAllUserAgents))
                            {
                                break;
                            }
                        }

                        userAgentsSoFar.Add(userAgent);
                        lastLineWasUserAgent = true;
                    }
                    else
                    {
                        if (this.IsAllowOrDisallowLine(line, out var allow, out var paths))
                        {
                            foreach (string path in paths)
                            {
                                rulesSoFar.Add(new Rule(path, allow, recordIndex));
                            }

                            lastLineWasUserAgent = false;
                        }
                        else if (this.IsExtensionLine(line)) // some future addition
                        {
                            lastLineWasUserAgent = false;
                        }
                    }
                }
            }

            // Commit the queued-up rules for the final block
            this.CommitRules(userAgentsSoFar, rulesSoFar.ToArray());
        }

        /// <summary>
        ///   Determines whether a named user agent is permitted to access the resource at a specified URI.
        /// </summary>
        /// <param name="userAgent"> The user agent token. </param>
        /// <param name="resource"> The URI for the resource that the user agent wishes to access. </param>
        /// <returns> True if the user agent is permitted to access the resource, else false. </returns>
        public bool IsAllowed([DisallowNull] string userAgent, [DisallowNull] Uri resource)
        {
            if (string.IsNullOrEmpty(userAgent) || resource == null)
            {
                throw new ArgumentNullException((userAgent == null) ? "userAgent" : "resource");
            }

            if (this.SiteBase == null)
            {
                throw new InvalidOperationException("The parser has not been initialised.");
            }

            if (!this.IsRfc1945Token(userAgent))
            {
                throw new InvalidUserAgentException(userAgent);
            }

            if (!string.Equals(resource.GetLeftPart(UriPartial.Authority), this.SiteBase.GetLeftPart(UriPartial.Authority).ToLower(), StringComparison.OrdinalIgnoreCase)) // different sites!
            {
                throw new SiteMismatchException();
            }

            string uri = resource.AbsolutePath;

            if (this.AllRestricted)
            {
                return false;
            }

            if (uri == "/robots.txt") // case-sensitive
            {
                return true; // "The /robots.txt URL is always allowed"
            }

            var knownAgent = this.FindMatchingUserAgent(userAgent);

            if (knownAgent != null) // if no matching agent, assume it's okay
            {
                var rulesForAgent = this.rulesForUserAgents[knownAgent];

                // "To evaluate if access to a URL is allowed, a robot must attempt to match
                // the paths in Allow and Disallow lines against the URL, in the order they
                // occur in the record. The first match found is used. If no match is found,
                // the default assumption is that the URL is allowed."

                foreach (Rule rule in rulesForAgent)
                {
                    if (this.IsPathMatch(uri, rule.PartialUri)) // here's our first match
                    {
                        return rule.Allow;
                    }
                }
            }

            return true;
        }

        /// <summary>
        ///   Generates a regular expression from a path that contains the asterisk wildcard ('*'), replacing the asterisk with '.*' (indicating any character sequence) and all other metacharacters with their escape codes.
        /// </summary>
        /// <param name="path"> The path. </param>
        /// <returns> The corresponding regular expression. </returns>
        private string? GetRegexFromWildcardPath([DisallowNull] string path)
        {
            string? escaped = null;

            for (int i = 0; i < path.Length; i++)
            {
                escaped += (path[i] == '*') ? ".*" : Regex.Escape(path[i].ToString(CultureInfo.InvariantCulture));
            }

            return escaped;
        }


        /// <summary>
        ///   Converts hexadecimal character escapes in a path to their corresponding single characters, except those that would interfere with path matching.
        /// </summary>
        /// <param name="path"> The path containing the hexadecimal escape sequences. </param>
        /// <returns> The path with any hexadecimal escape sequences replaced by their characters. </returns>
        private string? UnescapeForPathComparison(string path)
        {
            // "If a %xx encoded octet is encountered it is unencoded prior to comparison,
            // unless it is the '/' character, which has special meaning in a path."

            string? unescaped = null;

            if (path != null)
            {
                for (int i = 0; i < path.Length; i++)
                {
                    if (path[i] == '%' && i < path.Length - 2) // found %xx, i.e. all three chars
                    {
                        if (path.Substring(i, 3).ToLower() == "%2f") // don't unescape for '/'
                        {
                            unescaped += path.Substring(i, 3);
                            i += 2;
                        }
                        else // but do for any other characters (non-hex digits are okay here)
                        {
                            unescaped += Uri.HexUnescape(path, ref i); // this increases i for us
                            i--;
                        }
                    }
                    else // found some other character
                    {
                        unescaped += path[i];
                    }
                }
            }

            return unescaped;
        }


        /// <summary>
        ///   Determines whether one absolute path is considered to match another absolute path from a robot control file.
        /// </summary>
        /// <param name="ourPath"> The absolute path to be tested. </param>
        /// <param name="rulePath"> The path from the robot control file. </param>
        /// <returns> True if the first path is considered to match the second, else false. </returns>
        private bool IsPathMatch(string ourPath, string rulePath)
        {
            // 'ourPath' here *should* always be escaped, because of the Uri ctor's 'dontEscape'
            // parameter (the user either signals he has done it or gets the Uri ctor to do it).
            // However, you can create a Uri containing a raw '%' and specify true for 'dontEscape',
            // and that would cause matching issues where we compare e.g. '/%' with '/%2e'.
            // The best solution I can see is to reject any raw '%' in the input URI, since those
            // should be escaped (and I think the Uri class is wrong in not doing so); as long as
            // any URIs in the robot control file are escaped appropriately, all will be well.

            if (ContainsInvalidCharEscapes(ourPath))
            {
                throw new UriFormatException(
                    "The URI contains a '%' character that is not part of a hexadecimal character escape."
                    );
            }

            var match = false;

            ourPath = this.UnescapeForPathComparison(ourPath)!;
            rulePath = this.UnescapeForPathComparison(rulePath)!;

            if ((this.Options & ParseOptions.AsteriskWildcard) != 0 && rulePath.IndexOf("*", System.StringComparison.Ordinal) != -1)
            {
                string pattern = "^" + this.GetRegexFromWildcardPath(rulePath) + "$";

                match = Regex.IsMatch(ourPath, pattern);
            }
            else // standard matching without wildcards
            {
                match = ourPath.StartsWith(rulePath);
            }

            return match;
        }


        /// <summary>
        ///   Finds the user agent token from the robot control file that applies to a named robot.
        /// </summary>
        /// <param name="userAgent"> The robot's user agent token. </param>
        /// <returns> The matching user agent token from the file, or null if nothing matched. </returns>
        public string? FindMatchingUserAgent([DisallowNull] string userAgent)
        {
            string? bestMatch = null;

            if (this.rulesForUserAgents.ContainsKey(userAgent)) // exact match (case-insensitive)
            {
                bestMatch = userAgent;
            }
            else // look for the highest-priority substring match
            {
                var bestPriority = int.MaxValue;

                foreach (var entry in this.rulesForUserAgents)
                {
                    var thisAgent = (string)entry.Key;

                    if (thisAgent.ToLower().IndexOf(userAgent.ToLower(), System.StringComparison.Ordinal) != -1)
                    {
                        // Pick any of the user agent's rules to determine its priority

                        int thisPriority = this.rulesForUserAgents[thisAgent][0].Priority;

                        if (thisPriority < bestPriority) // lower is better
                        {
                            bestMatch = thisAgent;
                            bestPriority = thisPriority;
                        }
                    }
                }
            }

            // If we've still found nothing suitable, use the 'all user agents' token,
            // if the file had one. (If it didn't, we will have to return null.)

            if (bestMatch == null && this.rulesForUserAgents.ContainsKey(TokenAllUserAgents))
            {
                bestMatch = TokenAllUserAgents;
            }

            return bestMatch;
        }


        /// <summary>
        ///   Returns the URI at which the robot control file for a Web site is expected to reside.
        /// </summary>
        /// <param name="site"> The URI of the Web site or any file on it. </param>
        /// <returns> The expected URI of the robot control file. </returns>
        public Uri GetRobotsFileUri([DisallowNull] Uri site) => new Uri(site.GetLeftPart(UriPartial.Authority) + "/" + RobotsFileName);

        private string? GetHtmlMeta(string html, string meta)
        {
            try
            {
                var doc = new HtmlDocument();
                doc.LoadHtml(html);
                var node = doc.DocumentNode.SelectSingleNode("//meta[@name='" + meta + "']");
                return node.Attributes["content"].Value;
            }
            catch
            {
            }

            return null;
        }

        /// <summary>
        ///   Determines whether a named user agent is permitted to parse a document, or follow links from it
        /// </summary>
        /// <param name="userAgent"> The user agent token. </param>
        /// <param name="html"> Content of the downloaded html file </param>
        /// <returns> Policy bool[index rule, follow rule] </returns>
        public (bool CanIndex, bool CanFollow) CheckHtmlRobotMetaTag(string userAgent, [DisallowNull] string html)
        {
            if (!this.IsRfc1945Token(userAgent))
                throw new InvalidUserAgentException(userAgent);

            if (string.IsNullOrEmpty(html))
                throw new HtmlContentEmptyException("The HTML content can't be null");

            var bluebot = this.GetHtmlMeta(html, userAgent);
            var robot = this.GetHtmlMeta(html, "robots");

            // index, follow
            var index = new[] { true, true };
            string[]? policy = null;

            if (!string.IsNullOrEmpty(bluebot))
            {
                policy = bluebot.Split(',');
            }

            if (!string.IsNullOrEmpty(robot) && string.IsNullOrEmpty(bluebot))
            {
                policy = robot.Split(',');
            }

            if (policy == null)
            {
                return (true, true);
            }

            for (int i = 0; i < policy.Length; i++)
            {
                switch (policy[i].ToLower())
                {
                    case "index":
                    case "follow":
                    case "all":
                        break;
                    case "noindex":
                        index[0] = false;
                        break;
                    case "nofollow":
                        index[1] = false;
                        break;
                    case "none":
                        index[0] = false;
                        index[1] = false;
                        break;
                }
            }

            return (index[0], index[1]);
        }

        /// <summary>
        ///   Called when object is disposed
        /// </summary>
        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
