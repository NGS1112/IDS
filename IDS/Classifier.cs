namespace IDS
{
    public interface IClassifier
    {
        public void ClassifyAll(List<Packet> packs);

        public void Classify(Packet pack);

        public string ToString();
    }
}