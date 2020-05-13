using System;

namespace BlueCurve.Search.RobotRules.Abstractions
{
    /// <summary>
    ///   Indicates how a robot control file is to be parsed.
    /// </summary>
    [Flags]
    public enum ParseOptions
    {
        /// <summary>
        ///   None of the options are set.
        /// </summary>
        None = 0,

        /// <summary>
        ///   Field names in robot control files (such as "Allow" and "User-agent") are accepted in any combination of upper and lower case, not just the standard casing.
        /// </summary>
        IgnoreFieldNameCase = 1,

        /// <summary>
        ///   Blank Disallow lines are understood to mean that the user agent is allowed to access any URI on the site, as defined in 'A Standard for Robot Exclusion' (1994) but not the 1996 RFC Draft Memo.
        /// </summary>
        AcceptBlankDisallow = 2,

        /// <summary>
        ///   The asterisk character ('*') in robot control files should be interpreted as a wildcard representing any character sequence.
        /// </summary>
        /// <remarks>
        ///   Wildcard matching is not part of the robot control standard, under which '*' is a valid path character, but it is supported by Googlebot and possibly others.
        /// </remarks>
        AsteriskWildcard = 4,

        /// <summary>
        ///   All of the options are set.
        /// </summary>
        All = IgnoreFieldNameCase | AcceptBlankDisallow | AsteriskWildcard,

        /// <summary>
        ///   The default options are set.
        /// </summary>
        Defaults = All
    }
}