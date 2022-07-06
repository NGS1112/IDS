using System.Collections.Generic;

namespace IDS
{
/* Take this */
    class AnomalyClassifier : Classifier
    {
        // Trackers for total packets read, count of normal packets, and count of abnormal packets
        private int count;

        private int normal;
        private int actNormal;
        private int abnormal;
        private int actAbnormal;

        private int correct;

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
                if(pack.wrongFragment == 0 && pack.land == 0 && pack.service <= .62 && pack.failedLogins < 0.1 && pack.hot <= 0 && pack.srvCount <= 0.5110)
                {
                    pack.setClassification("Normal");
                    normal++;
                } 
                else
                {
                    pack.setClassification("Abnormal");
                    abnormal++;
                }

                findActual(pack);
            }
        }
        
        public void Classify(Packet pack)
        {
            count++;
            if(pack.wrongFragment == 0 && pack.land == 0 && pack.service <= .62 && pack.failedLogins < 0.1 && pack.hot <= 0 && pack.srvCount <= 0.5110)
            {
                pack.setClassification("Normal");
                normal++;
            } 
            else
            {
                pack.setClassification("Abnormal");
                abnormal++;
            }

            findActual(pack);
        }

        public void findActual(Packet p)
        {
            string actual = p.getActual();

            if(actual == "Normal")
            {
                actNormal++;
            } else
            {
                actAbnormal++;
            }

            if (actual == p.getClassification() || (actual != "Normal" && p.getClassification() == "Abnormal"))
            {
                correct++;
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
            return $"There are {count} packets in this file.\n" +
                   $"Normal packets Detected: {normal} of {actNormal}\n" +
                   $"Abnormal packets Detected: {abnormal} of {actAbnormal}" +
                   $"\nTotal Correctly Identified: {correct}";
        }
    }
}