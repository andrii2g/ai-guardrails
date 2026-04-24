namespace A2G.AIGuardrails.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
        var app = new CliApplication();
        return app.Run(args, Console.Out, Console.Error);
    }
}
