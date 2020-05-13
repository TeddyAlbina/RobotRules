using BlueCurve.Search.RobotRules.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace BlueCurve.Search.RobotRules.Microsoft.Extensions.DependencyInjection
{
    public static class RobotRulesExtensions
    {
        public static IServiceCollection AddRobotRulesCache<TRobotRulesCache>(this IServiceCollection serviceCollection)
            where TRobotRulesCache : class, IRobotRulesCache
            => serviceCollection.AddTransient<IRobotRulesCache, TRobotRulesCache>();

        public static IServiceCollection AddRobotRules(this IServiceCollection serviceCollection)
            => serviceCollection.AddTransient<IRobotFileParser, RobotsFileParser>();

        public static IServiceCollection AddRobotRules<TRobotsFileParser>(this IServiceCollection serviceCollection)
            where TRobotsFileParser : class, IRobotFileParser
            => serviceCollection.AddSingleton<IRobotFileParser, TRobotsFileParser>();
    }
}
