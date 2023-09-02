using Server;

class Program
{
    async static Task Main(string[] args)
    {
        CryptoServer server = new CryptoServer(8000); ;
        try
        {
            await server.start();
        }
        catch (Exception e) 
        {
            Console.WriteLine(e.Message);
        }
        
        return ;
    }
}

