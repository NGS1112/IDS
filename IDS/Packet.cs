namespace IDS
{
    public class Packet
    {
        // Strings to hold original data and classifications, used later for ToString()
        private readonly string? _originalData;
        private string _classification;

        public readonly double Protocol; // Protocol used for the connection
        public readonly double Service;  // Service requested during the connection
        public readonly double SrcBytes; // Bytes sent from source to host
        public readonly double DestBytes;// Bytes sent from host to source
        public readonly double Land; // flag for if destination adn source were the same
        public readonly double WrongFragment; // Number of broken fragments sent in a package
        public readonly double Hot;  // Indicators for entering a directory, executing a file, general changing/accessing data
        public readonly double FailedLogins; // Count of failed login attempts over the connection
        public readonly double LoginStatus;  // Indicates if the source was logged in to the destination
        //public readonly double OutCommands;  // Count of commands going from host to source
        public readonly double Count;    //Counter for how many recent connections have been made to the same host destination
        public readonly double SrvCount; // Counter for how many recent connections have been made to the same host port
        public readonly double SameSrvRate; // Rate of connections to the same service + srvCount
        public readonly double DstHostCount; // Counter for connections with same host IP address
        public readonly double DstHostSameServ; // Rate of connections to the same service + dstHostCount


        public Packet(string packet)
        {
            _originalData = packet; // Original string read in from file
            _classification = "Normal";
            string[] values = packet.Split(", "); // Splits strings on the ', ' delimiter

            // Grabs each feature from where it is in the string
            Protocol = Convert.ToDouble(values[1]);
            Service = Convert.ToDouble(values[2]);
            SrcBytes = Convert.ToDouble(values[4]);
            DestBytes = Convert.ToDouble(values[5]);
            Land = Convert.ToDouble(values[6]);
            WrongFragment = Convert.ToDouble(values[7]);
            Hot = Convert.ToDouble(values[9]);
            FailedLogins = Convert.ToDouble(values[10]);
            LoginStatus = Convert.ToDouble(values[11]);
            //OutCommands = Convert.ToDouble(values[19]);
            Count = Convert.ToDouble(values[22]);
            SrvCount = Convert.ToDouble(values[23]);
            SameSrvRate = Convert.ToDouble(values[28]);
            DstHostCount = Convert.ToDouble(values[31]);
            DstHostSameServ = Convert.ToDouble(values[33]);

        }

        public void SetClassification(string classified)
        {
            _classification = classified;
        }

        public string GetClassification()
        {
            return _classification;
        }
        
        /*
         * Function:    ToString
         * 
         * Output:   Original string used to create the packet object
         * 
         * Description: Returns the original string used to create the packet with the commas added back 
         *              in as well as the classification appended at the end.
         */
        public override string ToString()
        {
            return "Packet Data: " + _originalData + "; Classification: " + _classification;
        }
    }
}