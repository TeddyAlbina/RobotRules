using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace BlueCurve.Search.RobotRules.Abstractions
{
    public interface IRobotFileParser : IDisposable
    {
        bool AllRestricted { get; }
        string? LocalUserAgent { get; set; }
        ParseOptions Options { get; set; }
        Uri? SiteBase { get; }
        (bool CanIndex, bool CanFollow) CheckHtmlRobotMetaTag(string userAgent, [DisallowNull] string html);
        void Clear();
        string? FindMatchingUserAgent([DisallowNull] string userAgent);
        bool IsAllowed([DisallowNull] string userAgent, [DisallowNull] Uri resource);
        void Parse([DisallowNull] FileInfo file, [DisallowNull] Uri site);
        void Parse([DisallowNull] string[] robotsFileLines, [DisallowNull] Uri site);
        void Parse([DisallowNull] Uri site);
        void Parse([DisallowNull] Uri site, int timeout);
    }
}
