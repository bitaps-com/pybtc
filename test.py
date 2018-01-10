import unittest
import test

testLoad = unittest.TestLoader()
suites = testLoad.loadTestsFromModule(test)

runner = unittest.TextTestRunner(verbosity=2)
runner.run(suites)
