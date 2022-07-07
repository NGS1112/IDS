namespace TestIDS
{
    public class TestAnomaly
    {
        private Classifier test;
        
        [SetUp]
        public void Setup()
        {
            test = new AnomalyClassifier();
        }

        [Test]
        public void TestConstructor()
        {
            Assert.NotNull(test);
        }
        
        [Test]
        public void TestClassifyAll()
        {
            Assert.Pass();
        }

        [Test]
        public void TestClassify()
        {
            Assert.Pass();
        }
        
        [Test]
        public void TestToString()
        {
            Assert.Pass();
        }
    }
}