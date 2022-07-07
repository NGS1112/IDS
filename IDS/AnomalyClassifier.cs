using System.Collections.Generic;

namespace IDS
{
    class AnomalyClassifier : Classifier
    {
        // Trackers for total packets read, count of normal packets, and count of abnormal packets
        private int count;

        private int normal;
        private int anomaly;

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
                count++;
                if(pack.WrongFragment == 0 && pack.Land == 0 && pack.Service <= .62 && pack.FailedLogins < 0.1 && pack.Hot <= 0 && pack.SrvCount <= 0.5110)
                {
                    normal++;
                    pack.SetClassification("Normal");
                } 
                else
                {
                    anomaly++;
                    pack.SetClassification("Anomaly");
                }
            }
        }
        
        public void Classify(Packet pack)
        {
            count++;
            if(pack.WrongFragment == 0 && pack.Land == 0 && pack.Service <= .62 && pack.FailedLogins < 0.1 && pack.Hot <= 0 && pack.SrvCount <= 0.5110)
            {
                normal++;
                pack.SetClassification("Normal");
            } 
            else
            {
                anomaly++;
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
            return $"There were {count} packets detected." +
                   $"\nNormal packets Detected: {normal}" +
                   $"\nAbnormal packets Detected: {anomaly}";
        }
    }
}