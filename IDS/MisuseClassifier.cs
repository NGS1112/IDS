namespace IDS
{
    internal class MisuseClassifier : IClassifier
    {
        // Counters to be used for tracking instances of each attack / normal connections
        private int _count, _norm, _tear, _smurf, _root, _guess, _back;

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
                var attackDetected = false;
                _count++;
                
                switch (pack.Protocol) // Switches by the protocol used to establish connection. If attack detected, raise flag and change classification
                {
                    case 0: // If connection is TCP, check for GuessPassword / RootKit / BackDoor
                        if (IsGuessPassword(pack))
                        {
                            pack.SetClassification("GuessPassword");
                            _guess++;
                            attackDetected = true;
                        }
                        else if (IsRootKit(pack, true))
                        {
                            pack.SetClassification("RootKit");
                            _root++;
                            attackDetected = true;
                        }
                        else if (IsBackDoor(pack))
                        {
                            pack.SetClassification("BackDoor");
                            _back++;
                            attackDetected = true;
                        }
                        break;
                    case 0.0100: // If connection is UCP, check for Teardrop / RootKit / Smurf
                        if (IsTearDrop(pack))
                        {
                            pack.SetClassification("TearDrop");
                            _tear++;
                            attackDetected = true;
                        }
                        else if (IsRootKit(pack, false))
                        {
                            pack.SetClassification("RootKit");
                            _root++;
                            attackDetected = true;
                        }
                        else if (IsSmurf(pack))
                        {
                            pack.SetClassification("Smurf");
                            _smurf++;
                            attackDetected = true;
                        }
                        break;
                    case 0.0200: // If connection is ICMP, check for Smurf
                        if (IsSmurf(pack))
                        {
                            pack.SetClassification("Smurf");
                            _smurf++;
                            attackDetected = true;
                        }
                        break;
                }

                if (attackDetected) continue;
                pack.SetClassification("Normal");
                _norm++;
            }
        }
        
        public void Classify(Packet pack)
        {
            // Initialize attack detector to false and increment the count of packets processed
            bool attackDetected = false;
            _count++;
            switch (pack.Protocol) // Switches by the protocol used to establish connection. If attack detected, raise flag and change classification
            {
                case 0: // If connection is TCP, check for GuessPassword / RootKit / BackDoor
                    if (IsGuessPassword(pack))
                    {
                        pack.SetClassification("GuessPassword");
                        _guess++;
                        attackDetected = true;
                    }
                    else if (IsRootKit(pack, true))
                    {
                        pack.SetClassification("RootKit");
                        _root++;
                        attackDetected = true;
                    }
                    else if (IsBackDoor(pack))
                    {
                        pack.SetClassification("BackDoor");
                        _back++;
                        attackDetected = true;
                    }
                    break;
                case 0.0100: // If connection is UCP, check for Teardrop / RootKit / Smurf
                    if (IsTearDrop(pack))
                    {
                        pack.SetClassification("TearDrop");
                        _tear++;
                        attackDetected = true;
                    }
                    else if (IsRootKit(pack, false))
                    {
                        pack.SetClassification("RootKit");
                        _root++;
                        attackDetected = true;
                    }
                    else if (IsSmurf(pack))
                    {
                        pack.SetClassification("Smurf");
                        _smurf++;
                        attackDetected = true;
                    }
                    break;
                case 0.0200: // If connection is ICMP, check for Smurf
                    if (IsSmurf(pack))
                    {
                        pack.SetClassification("Smurf");
                        _smurf++;
                        attackDetected = true;
                    }
                    break;
            }

            if (attackDetected) return;
            pack.SetClassification("Normal");
            _norm++;
        }

        /*
         * Function:    IsTearDrop
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is TearDrop attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is sending broken fragments in an attempt to 
         *              exploit a flaw in the system involving overlapping fragments causing a crash.
         */
        private static bool IsTearDrop(Packet p)
        {
            // If the packet contained broken fragments that could overlap, return true
            return p.WrongFragment != 0;
        }

        /*
         * Function:    IsGuessPassword
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is GuessPassword attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is coming from a host repetitively trying and failing
         *              to log into the network with different passwords.
         */
        private static bool IsGuessPassword(Packet p)
        {
            // If high level of failed logins, matching count of non-unique connections, user is trying to access data, and user is not logged in, return true
            return p.FailedLogins >= 0.1 && Math.Abs(p.Count - p.SrvCount) < 0.001 && p.Hot >= 0.1 && p.LoginStatus == 0;
        }

        /*
         * Function:    IsSmurf
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is Smurf attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is using the echo service request from the same
         *              spoofed address in an attempt to overload the network.
         */
        private static bool IsSmurf(Packet p)
        {
            // If count is close to srvCount and the service tag indicates an echo request being relayed, return true
            return (Math.Abs(p.Count - p.SrvCount) < 0.0015 || Math.Abs(p.Count - p.SrvCount) < 0.001 ) && (Math.Abs(p.Service - 0.0900) < 0.001 || Math.Abs(p.Service - 0.1200) < 0.001);
        }

        /*
         * Function:    IsRootKit
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is RootKit attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is transmitting large amounts of data utilizing a 
         *              rootkit downloaded onto the host machine.
         */
        private static bool IsRootKit(Packet p, bool tcp)
        {
            if (tcp) // Check which protocol is being used for this specific packet
            {
                // If TCP and service is above .05, destBytes are higher than srcBytes, the counts are the same with differences around host, return true
                return p.Service >= 0.05 && p.SrcBytes <= p.DestBytes && Math.Abs(p.Count - p.SrvCount) < 0.001 && p.DstHostCount > 0.2 && Math.Abs(p.SameSrvRate - 0.1) < 0.001;
            }
            
            // If not TCP and service is at 0.1, source bytes are higher than destBytes, and the counts are the same, return true
            return Math.Abs(p.Service - 0.1) < 0.001 && p.SrcBytes >= p.DestBytes && Math.Abs(p.Count - p.SrvCount) < 0.001;

        }

        /*
         * Function:    IsBackDoor
         * 
         * Input:   Packet to be classified
         * 
         * Output:  Boolean that is true if Packet is BackDoor attack, false otherwise
         * 
         * Description: Classifies the packet based on if it is continuosly recieving data from the host without 
         *              requesting service as well as being constantly logged in. 
         */
        private static bool IsBackDoor(Packet p)
        {
            // If no service requested, data is being altered, user is logged in, and the counts are similar, return true
            return p.Service == 0 
                   && p.Hot >= 0.1 && Math.Abs(p.LoginStatus - 0.1) < 0.001 &&
                   (Math.Abs(p.Count - p.SrvCount) < 0.001 || Math.Abs(p.Count - p.SrvCount) < 0.0025 || Math.Abs(p.Count - p.SrvCount) < 0.0015) && p.DstHostSameServ >= 0.1;
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
            return $"There were {_count} packets detected." + $"\nNormal Detected: {_norm}"
                + $"\nTearDrop Detected: {_tear}" + $"\nSmurf Detected: {_smurf}" + $"\nRoot Detected: {_root}" 
                + $"\nGuessPassword Detected: {_guess}" + $"\nBackdoor Detected: {_back}";
        }
    }
}