using System.Collections.Generic;

namespace IDS
{
    class MisuseClassifier : Classifier
    {
        // Counters to be used for tracking instances of each attack / normal connections
        private int count = 0;

        private int norm = 0;
        private int tear = 0;
        private int smurf = 0;
        private int root = 0;
        private int guess = 0;
        private int back = 0;

        /*
         * Function: classify
         * 
         * Input:   List of packets to be classified
         * 
         * Description: Processes the packets in the list one at a time, comparing them to known
         *              attack characteristics. If data matches, mark the packet with which attack it is.
         *              Otherwise, mark it as normal.
         */
        public void ClassifyAll(List<Packet> packs)
        {
            foreach (Packet pack in packs) // Loops through all packets in the list
            {
                // Initialize attack detector to false and increment the count of packets processed
                bool attackDetected = false;
                count++;
                
                switch (pack.Protocol) // Switches by the protocol used to establish connection. If attack detected, raise flag and change classification
                {
                    case 0: // If connection is TCP, check for GuessPassword / RootKit / BackDoor
                        if (isGuessPassword(pack))
                        {
                            pack.SetClassification("GuessPassword");
                            guess++;
                            attackDetected = true;
                        }
                        else if (isRootKit(pack, true))
                        {
                            pack.SetClassification("RootKit");
                            root++;
                            attackDetected = true;
                        }
                        else if (isBackDoor(pack))
                        {
                            pack.SetClassification("BackDoor");
                            back++;
                            attackDetected = true;
                        }
                        break;
                    case 0.0100: // If connection is UCP, check for Teardrop / RootKit / Smurf
                        if (isTearDrop(pack))
                        {
                            pack.SetClassification("TearDrop");
                            tear++;
                            attackDetected = true;
                        }
                        else if (isRootKit(pack, false))
                        {
                            pack.SetClassification("RootKit");
                            root++;
                            attackDetected = true;
                        }
                        else if (isSmurf(pack))
                        {
                            pack.SetClassification("Smurf");
                            smurf++;
                            attackDetected = true;
                        }
                        break;
                    case 0.0200: // If connection is ICMP, check for Smurf
                        if (isSmurf(pack))
                        {
                            pack.SetClassification("Smurf");
                            smurf++;
                            attackDetected = true;
                        }
                        break;
                }
                if (!attackDetected) // If no attacks were detected, mark this packet normal
                {
                    pack.SetClassification("Normal");
                    norm++;
                }
            }
        }
        
        public void Classify(Packet pack)
        {
            // Initialize attack detector to false and increment the count of packets processed
            bool attackDetected = false;
            count++;
            switch (pack.Protocol) // Switches by the protocol used to establish connection. If attack detected, raise flag and change classification
            {
                case 0: // If connection is TCP, check for GuessPassword / RootKit / BackDoor
                    if (isGuessPassword(pack))
                    {
                        pack.SetClassification("GuessPassword");
                        guess++;
                        attackDetected = true;
                    }
                    else if (isRootKit(pack, true))
                    {
                        pack.SetClassification("RootKit");
                        root++;
                        attackDetected = true;
                    }
                    else if (isBackDoor(pack))
                    {
                        pack.SetClassification("BackDoor");
                        back++;
                        attackDetected = true;
                    }
                    break;
                case 0.0100: // If connection is UCP, check for Teardrop / RootKit / Smurf
                    if (isTearDrop(pack))
                    {
                        pack.SetClassification("TearDrop");
                        tear++;
                        attackDetected = true;
                    }
                    else if (isRootKit(pack, false))
                    {
                        pack.SetClassification("RootKit");
                        root++;
                        attackDetected = true;
                    }
                    else if (isSmurf(pack))
                    {
                        pack.SetClassification("Smurf");
                        smurf++;
                        attackDetected = true;
                    }
                    break;
                case 0.0200: // If connection is ICMP, check for Smurf
                    if (isSmurf(pack))
                    {
                        pack.SetClassification("Smurf");
                        smurf++;
                        attackDetected = true;
                    }
                    break;
            }
            if (!attackDetected) // If no attacks were detected, mark this packet normal
            {
                pack.SetClassification("Normal");
                norm++;
            }
        }

        /*
         * Function:    isTearDrop
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is TearDrop attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is sending broken fragments in an attempt to 
         *              exploit a flaw in the system involving overlapping fragments causing a crash.
         */
        public bool isTearDrop(Packet p)
        {
            // If the packet contained broken fragments that could overlap, return true
            if (p.WrongFragment != 0)
            {
                return true;
            } 
            else    // Otherwise, return false
            {
                return false;
            }
        }

        /*
         * Function:    isGuessPassword
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is GuessPassword attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is coming from a host repetitively trying and failing
         *              to log into the network with different passwords.
         */
        public bool isGuessPassword(Packet p)
        {
            // If high level of failed logins, matching count of non-unique connections, user is trying to access data, and user is not logged in, return true
            if (p.FailedLogins >= 0.1 && p.Count == p.SrvCount && p.Hot >= 0.1 && p.LoginStatus == 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /*
         * Function:    isSmurf
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is Smurf attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is using the echo service request from the same
         *              spoofed address in an attempt to overload the network.
         */
        public bool isSmurf(Packet p)
        {
            // If count is close to srvCount and the service tag indicates an echo request being relayed, return true
            if ( (p.Count + 0.001 == p.SrvCount || p.Count == p.SrvCount ) && (p.Service == 0.0900 || p.Service == 0.1200) )
            {
               return true;
           }                                         
           else
            {
                return false;
            }
        }

        /*
         * Function:    isRootKit
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is RootKit attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is transmitting large amounts of data utilizing a 
         *              rootkit downloaded onto the host machine.
         */
        public bool isRootKit(Packet p, bool tcp)
        {
            if (tcp) // Check which protocol is being used for this specific packet
            {
                // If TCP and service is above .05, destBytes are higher than srcBytes, the counts are the same with differences around host, return true
                if (p.Service >= 0.05 && p.SrcBytes <= p.DestBytes && p.Count == p.SrvCount && p.DstHostCount > 0.2 && p.SameSrvRate == 0.1)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            } else
            {
                // If not TCP and service is at 0.1, source bytes are higher than destBytes, and the counts are the same, return true
                if (p.Service == 0.1 && p.SrcBytes >= p.DestBytes && p.Count == p.SrvCount)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        /*
         * Function:    isBackDoor
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is BackDoor attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is continuosly recieving data from the host without 
         *              requesting service as well as being constantly logged in. 
         */
        public bool isBackDoor(Packet p)
        {
            // If no service requested, data is being altered, user is logged in, and the counts are similar, return true
            if (p.Service == 0 
                && p.Hot >= 0.1 && p.LoginStatus == 0.1 &&
                (p.Count == p.SrvCount || p.Count + 0.002 == p.SrvCount || p.Count + 0.001 == p.SrvCount) && p.DstHostSameServ >= 0.1)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /*
         * Function:    ToString
         * 
         * Output:  String representation of the classifier including the count of each type of packet processed
         * 
         * Description: Returns a string containing all of the counters collected during classification for analysis.
         */
        public override string ToString()
        {
            return $"There were {count} packets detected." + $"\nNormal Detected: {norm}"
                + $"\nTearDrop Detected: {tear}" + $"\nSmurf Detected: {smurf}" + $"\nRoot Detected: {root}" 
                + $"\nGuessPassword Detected: {guess}" + $"\nBackdoor Detected: {back}";
        }
    }
}