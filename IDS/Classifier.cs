using System;
using System.Collections.Generic;

namespace IDS
{
    public interface Classifier
    {
        public void ClassifyAll(List<Packet> packs);

        public void Classify(Packet pack);

        public string ToString();
    }
}