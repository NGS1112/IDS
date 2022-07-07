namespace TestIDS
{
    public class TestMisuse
    {
        private Classifier test;
        
        [SetUp]
        public void Setup()
        {
            test = new MisuseClassifier();
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