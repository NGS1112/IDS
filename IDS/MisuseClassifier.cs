using System.Collections.Generic;

namespace IDS
{
    class MisuseClassifier
    {
        // Counters to be used for tracking instances of each attack / normal connections
        private int count = 0;

        private int norm = 0;
        private int actNorm = 0;
        private int tear = 0;
        private int actTear = 0;
        private int smurf = 0;
        private int actSmurf = 0;
        private int root = 0;
        private int actRoot = 0;
        private int guess = 0;
        private int actGuess = 0;
        private int back = 0;
        private int actBack = 0;

        private int correct = 0;

        /*
         * Function: classify
         * 
         * Input:   List of packets to be classified
         * 
         * Description: Processes the packets in the list one at a time, comparing them to known
         *              attack characteristics. If data matches, mark the packet with which attack it is.
         *              Otherwise, mark it as normal.
         */
        public void classify(List<Packet> packs)
        {
            foreach (Packet pack in packs) // Loops through all packets in the list
            {
                // Initialize attack detector to false and increment the count of packets processed
                bool attackDetected = false;
                count++;

                switch (pack.protocol) // Switches by the protocol used to establish connection. If attack detected, raise flag and change classification
                {
                    case 0: // If connection is TCP, check for GuessPassword / RootKit / BackDoor
                        if (isGuessPassword(pack))
                        {
                            pack.setClassification("GuessPassword");
                            guess++;
                            attackDetected = true;
                        }
                        else if (isRootKit(pack, true))
                        {
                            pack.setClassification("RootKit");
                            root++;
                            attackDetected = true;
                        }
                        else if (isBackDoor(pack))
                        {
                            pack.setClassification("BackDoor");
                            back++;
                            attackDetected = true;
                        }
                        break;
                    case 0.0100: // If connection is UCP, check for Teardrop / RootKit / Smurf
                        if (isTearDrop(pack))
                        {
                            pack.setClassification("TearDrop");
                            tear++;
                            attackDetected = true;
                        }
                        else if (isRootKit(pack, false))
                        {
                            pack.setClassification("RootKit");
                            root++;
                            attackDetected = true;
                        }
                        else if (isSmurf(pack))
                        {
                            pack.setClassification("Smurf");
                            smurf++;
                            attackDetected = true;
                        }
                        break;
                    case 0.0200: // If connection is ICMP, check for Smurf
                        if (isSmurf(pack))
                        {
                            pack.setClassification("Smurf");
                            smurf++;
                            attackDetected = true;
                        }
                        break;
                    default:
                        break;
                }

                if (!attackDetected) // If no attacks were detected, mark this packet normal
                {
                    pack.setClassification("Normal");
                    norm++;
                }

                findActual(pack);
            }

        }

        public void findActual(Packet p)
        {
            string actual = p.getActual();

            switch(actual){
                case "Normal":
                    actNorm++;
                    break;
                case "RootKit":
                    actRoot++;
                    break;
                case "BackDoor":
                    actBack++;
                    break;
                case "Smurf":
                    actSmurf++;
                    break;
                case "GuessPassword":
                    actGuess++;
                    break;
                case "TearDrop":
                    actTear++;
                    break;
                default:
                    break;
            }

            if(actual == p.getClassification())
            {
                correct++;
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
            if (p.wrongFragment != 0)
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
            if (p.failedLogins >= 0.1 && p.count == p.srvCount && p.hot >= 0.1 && p.loginStatus == 0)
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
            if ( (p.count + 0.001 == p.srvCount || p.count == p.srvCount ) && (p.service == 0.0900 || p.service == 0.1200) )
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
                if (p.service >= 0.05 && p.srcBytes <= p.destBytes && p.count == p.srvCount && p.dstHostCount > 0.2 && p.sameSrvRate == 0.1)
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
                if (p.service == 0.1 && p.srcBytes >= p.destBytes && p.count == p.srvCount)
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
            if (p.service == 0 
                && p.hot >= 0.1 && p.loginStatus == 0.1 &&
                (p.count == p.srvCount || p.count + 0.002 == p.srvCount || p.count + 0.001 == p.srvCount) && p.dstHostSameServ >= 0.1)
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
            return $"There are {count} packets in this file" + $"\nNormal Detected: {norm} of {actNorm}"
                + $"\nTearDrop Detected: {tear} of {actTear}" + $"\nSmurf Detected: {smurf} of {actSmurf}" + $"\nRoot Detected: {root} of {actRoot}" + $"\nGuessPassword Detected: {guess} of {actGuess}"
                 + $"\nBackdoor Detected: {back} of {actBack}" +
                 $"\nTotal Correctly Identified: {correct}";
        }
    }
}