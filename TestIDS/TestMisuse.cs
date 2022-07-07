namespace TestIDS
{
    public class TestMisuse
    {
        private IClassifier _test;
        
        [SetUp]
        public void Setup()
        {
            _test = new MisuseClassifier();
        }

        [Test]
        public void TestConstructor()
        {
            Assert.NotNull(_test);
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