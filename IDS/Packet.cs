using System;

namespace IDS
{
    public class Packet
    {
        // Strings to hold original data and classifications, used later for ToString()
        private string originalData;
        private string classification;
        private string actualType;

        public double protocol; // Protocol used for the connection
        public double service;  // Service requested during the connection
        public double srcBytes; // Bytes sent from source to host
        public double destBytes;// Bytes sent from host to source
        public double land; // flag for if destination adn source were the same
        public double wrongFragment; // Number of broken fragments sent in a package
        public double hot;  // Indicators for entering a directory, executing a file, general changing/accessing data
        public double failedLogins; // Count of failed login attempts over the connection
        public double loginStatus;  // Indicates if the source was logged in to the destination
        public double outCmds;  // Count of commands going from host to source
        public double count;    //Counter for how many recent connections have been made to the same host destination
        public double srvCount; // Counter for how many recent connections have been made to the same host port
        public double sameSrvRate; // Rate of connections to the same service + srvCount
        public double dstHostCount; // Counter for connections with same host IP address
        public double dstHostSameServ; // Rate of connections to the same service + dstHostCount


        public Packet(string packet, string type)
        {
            originalData = packet; // Original string read in from file
            string[] values = packet.Split(", "); // Splits strings on the ', ' delimeter

            // Grabs each feature from where it is in the string
            protocol = Convert.ToDouble(values[1]);
            service = Convert.ToDouble(values[2]);
            srcBytes = Convert.ToDouble(values[4]);
            destBytes = Convert.ToDouble(values[5]);
            land = Convert.ToDouble(values[6]);
            wrongFragment = Convert.ToDouble(values[7]);
            hot = Convert.ToDouble(values[9]);
            failedLogins = Convert.ToDouble(values[10]);
            loginStatus = Convert.ToDouble(values[11]);
            outCmds = Convert.ToDouble(values[19]);
            count = Convert.ToDouble(values[22]);
            srvCount = Convert.ToDouble(values[23]);
            sameSrvRate = Convert.ToDouble(values[28]);
            dstHostCount = Convert.ToDouble(values[31]);
            dstHostSameServ = Convert.ToDouble(33);

            actualType = type;
        }

        /*
         * Function:    setClassification
         * 
         * Input:   String to be used as classification
         * 
         * Description: Setter for this packets classification.
         */
        public void setClassification(string classifier)
        {
            classification = classifier;
        }

        /*
         * Function:    getClassification
         * 
         * Output:   String used as classification
         * 
         * Description: Getter for the packets classification.
         */
        public string getClassification()
        {
            return classification;
        }

        public string getActual()
        {
            return actualType;
        }

        /*
         * Function:    ToSTring
         * 
         * Output:   Oiginal string used to create the packet object
         * 
         * Description: Returns the original string used to create the packet with the commas added back 
         *              in as well as the classification appended at the end.
         */
        public override string ToString()
        {
            return originalData + ", " + classification;
        }
    }
}