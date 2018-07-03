import unittest

import pybtc.test

testLoad = unittest.TestLoader()
suites = testLoad.loadTestsFromModule(pybtc.test)

runner = unittest.TextTestRunner(verbosity=1)
runner.run(suites)
