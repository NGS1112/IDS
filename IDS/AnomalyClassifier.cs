namespace IDS
{
    internal class AnomalyClassifier : IClassifier
    {
        // Trackers for total packets read, count of normal packets, and count of abnormal packets
        private int _count;

        private int _normal;
        private int _anomaly;

        /*
         * Function: classify
         * 
         * Input: List of packets to be classified
         * 
         * Description: Classifies packets based on the normal pattern of an average packet. If packet data deviates
         *              from normal metrics, marks it abnormal. 
         */
        public void ClassifyAll(List<Packet> packs)
        {
            foreach(Packet pack in packs)
            {
                _count++;
                if(pack.WrongFragment == 0 && pack.Land == 0 && pack.Service <= .62 && pack.FailedLogins < 0.1 && pack.Hot <= 0 && pack.SrvCount <= 0.5110)
                {
                    _normal++;
                    pack.SetClassification("Normal");
                } 
                else
                {
                    _anomaly++;
                    pack.SetClassification("Anomaly");
                }
            }
        }
        
        public void Classify(Packet pack)
        {
            _count++;
            if(pack.WrongFragment == 0 && pack.Land == 0 && pack.Service <= .62 && pack.FailedLogins < 0.1 && pack.Hot <= 0 && pack.SrvCount <= 0.5110)
            {
                _normal++;
                pack.SetClassification("Normal");
            } 
            else
            {
                _anomaly++;
                pack.SetClassification("Anomaly");
            }
        }

        /*
         * Function: ToString()
         * 
         * Return:  String representing the amount of packets processed, how many were normal, and how many were abnormal
         * 
         * Description: String representation of the data gained from classifying the packets 
         */
        public override string ToString()
        {
            return $"There were {_count} packets detected." +
                   $"\nNormal packets Detected: {_normal}" +
                   $"\nAbnormal packets Detected: {_anomaly}";
        }
    }
}